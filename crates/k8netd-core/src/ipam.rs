//! In-memory IPAM allocator for one network (spec REQ-004, VC-03).
//!
//! TASK-006 (test-first): the `tests` module below defines the contract for
//! the allocator. The allocator does not exist yet, so the tests fail to
//! compile (red phase). TASK-007 implements the allocator in this file to
//! make the tests pass; the tests module stays at the bottom of the file per
//! Rust convention.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::model::{MacAddr, Network};

/// Error type for IPAM allocation failures (spec REQ-004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpamError {
    /// Every address in the pool is already bound to a MAC.
    PoolExhausted,
    /// `release()` was called for a MAC with no active allocation.
    UnknownMac,
}

impl fmt::Display for IpamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpamError::PoolExhausted => write!(f, "IP pool exhausted"),
            IpamError::UnknownMac => write!(f, "no allocation for the given MAC"),
        }
    }
}

impl std::error::Error for IpamError {}

/// In-memory IPAM allocator for one network (spec REQ-004).
///
/// Allocates the lowest free address in the network's pool and binds it to a
/// MAC as a DHCP reservation; the same MAC always receives the same IP while
/// its allocation is active. The gateway is never allocated because
/// `Network::new` rejects pools that contain it.
#[derive(Debug)]
pub struct Ipam {
    network: Network,
    allocations: HashMap<MacAddr, Ipv4Addr>,
}

impl Ipam {
    /// Creates an allocator for the given network with no active allocations.
    pub fn new(network: Network) -> Self {
        Ipam {
            network,
            allocations: HashMap::new(),
        }
    }

    /// Allocates the lowest free address in the pool and binds it to `mac`.
    ///
    /// Returns the existing binding when `mac` already has an allocation
    /// (reservation semantics), or `Err(IpamError::PoolExhausted)` when every
    /// pool address is bound.
    pub fn allocate(&mut self, mac: MacAddr) -> Result<Ipv4Addr, IpamError> {
        if let Some(ip) = self.allocations.get(&mac) {
            return Ok(*ip);
        }
        let start = u32::from(self.network.pool.start);
        let end = u32::from(self.network.pool.end);
        for candidate in start..=end {
            let ip = Ipv4Addr::from(candidate);
            if !self.allocations.values().any(|bound| *bound == ip) {
                self.allocations.insert(mac, ip);
                return Ok(ip);
            }
        }
        Err(IpamError::PoolExhausted)
    }

    /// Frees the IP bound to `mac` for reuse.
    ///
    /// Returns `Err(IpamError::UnknownMac)` when `mac` has no active
    /// allocation.
    pub fn release(&mut self, mac: MacAddr) -> Result<(), IpamError> {
        if self.allocations.remove(&mac).is_none() {
            return Err(IpamError::UnknownMac);
        }
        Ok(())
    }

    /// Returns the IP bound to `mac`, if any.
    pub fn lookup(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        self.allocations.get(&mac).copied()
    }
}

#[cfg(test)]
mod tests {
    // Expected API — implemented by TASK-007 to satisfy these tests:
    //
    // pub enum IpamError {
    //     PoolExhausted,  // every address in the pool is already bound
    //     UnknownMac,     // release() called for a MAC with no allocation
    // }
    //   - Debug, Clone, PartialEq, Eq
    //
    // pub struct Ipam { ... }
    //   - Ipam::new(network: Network) -> Ipam
    //   - allocate(&mut self, mac: MacAddr) -> Result<Ipv4Addr, IpamError>
    //       - returns the lowest free address in the pool (deterministic
    //         order, plan TASK-007 constraint)
    //       - returns the same IP for the same MAC while the allocation is
    //         active (reservation semantics, spec REQ-004)
    //       - never returns the gateway or any address outside the pool
    //         (Network::new already rejects pools containing the gateway)
    //       - Err(IpamError::PoolExhausted) when every pool address is bound
    //   - release(&mut self, mac: MacAddr) -> Result<(), IpamError>
    //       - frees the IP bound to mac for reuse
    //       - Err(IpamError::UnknownMac) for a MAC with no active allocation
    //         (pinned behavior: release of an unknown MAC is an error, not a
    //         no-op; the RPC layer maps it to `not_found`)
    //   - lookup(&self, mac: MacAddr) -> Option<Ipv4Addr>
    //       - Some(ip) while the allocation is active, None after release or
    //         if never allocated

    use super::*;
    use crate::model::{IpPool, MacAddr, Network};
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    fn pool(start: Ipv4Addr, end: Ipv4Addr) -> IpPool {
        IpPool::new(start, end).unwrap()
    }

    fn lab_network(gateway: Ipv4Addr, pool: IpPool) -> Network {
        Network::new("lab", "192.168.124.0/24", &gateway.to_string(), pool).unwrap()
    }

    // REQ-1: Allocation from the pool returns an address inside the pool.

    #[test]
    fn allocate_returns_address_inside_pool() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 200)),
        ));
        let allocated = ipam
            .allocate(mac("02:00:00:00:00:01"))
            .expect("pool has free addresses");
        let start = u32::from(ip(192, 168, 124, 10));
        let end = u32::from(ip(192, 168, 124, 200));
        assert!(
            u32::from(allocated) >= start && u32::from(allocated) <= end,
            "allocated {allocated} is outside the pool"
        );
    }

    #[test]
    fn allocate_returns_lowest_free_address() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        assert_eq!(ipam.allocate(mac("02:00:00:00:00:01")).unwrap(), ip(192, 168, 124, 10));
    }

    // REQ-2: IP<->MAC binding — the same MAC always gets the same IP.

    #[test]
    fn same_mac_gets_same_ip() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        let first = ipam.allocate(mac("02:00:00:00:00:01")).unwrap();
        let second = ipam.allocate(mac("02:00:00:00:00:01")).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn lookup_returns_bound_ip() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        let allocated = ipam.allocate(mac("02:00:00:00:00:01")).unwrap();
        assert_eq!(ipam.lookup(mac("02:00:00:00:00:01")), Some(allocated));
    }

    // REQ-3: Release frees the IP for reuse.

    #[test]
    fn release_frees_ip_for_reuse() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        let a = ipam.allocate(mac("02:00:00:00:00:01")).unwrap(); // .10
        let _b = ipam.allocate(mac("02:00:00:00:00:02")).unwrap(); // .11
        ipam.release(mac("02:00:00:00:00:01")).unwrap();
        let c = ipam.allocate(mac("02:00:00:00:00:03")).unwrap();
        assert_eq!(c, a, "the freed .10 must be reusable");
    }

    #[test]
    fn release_removes_binding() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        ipam.allocate(mac("02:00:00:00:00:01")).unwrap();
        ipam.release(mac("02:00:00:00:00:01")).unwrap();
        assert_eq!(ipam.lookup(mac("02:00:00:00:00:01")), None);
    }

    #[test]
    fn release_unknown_mac_returns_error() {
        // Pinned behavior (edge case): releasing a MAC with no active
        // allocation is an error (IpamError::UnknownMac), not a no-op.
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        assert_eq!(ipam.release(mac("02:00:00:00:00:ff")), Err(IpamError::UnknownMac));
    }

    // REQ-4: Pool exhaustion returns an error.

    #[test]
    fn pool_exhaustion_returns_error() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        ipam.allocate(mac("02:00:00:00:00:01")).unwrap();
        ipam.allocate(mac("02:00:00:00:00:02")).unwrap();
        ipam.allocate(mac("02:00:00:00:00:03")).unwrap();
        assert_eq!(ipam.allocate(mac("02:00:00:00:00:04")), Err(IpamError::PoolExhausted));
    }

    #[test]
    fn allocation_after_exhaustion_post_release() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        ipam.allocate(mac("02:00:00:00:00:01")).unwrap(); // .10
        ipam.allocate(mac("02:00:00:00:00:02")).unwrap(); // .11
        ipam.allocate(mac("02:00:00:00:00:03")).unwrap(); // .12
        assert_eq!(ipam.allocate(mac("02:00:00:00:00:04")), Err(IpamError::PoolExhausted));
        ipam.release(mac("02:00:00:00:00:01")).unwrap();
        let again = ipam.allocate(mac("02:00:00:00:00:04")).unwrap();
        assert_eq!(
            again,
            ip(192, 168, 124, 10),
            "the freed .10 must be reused after exhaustion"
        );
    }

    // REQ-5: The gateway address is never allocated.

    #[test]
    fn gateway_adjacent_to_pool_start_never_allocated() {
        // Gateway sits just below the pool start; the allocator must never
        // hand it out even when the whole pool is allocated.
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 9),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        let ips = [
            ipam.allocate(mac("02:00:00:00:00:01")).unwrap(),
            ipam.allocate(mac("02:00:00:00:00:02")).unwrap(),
            ipam.allocate(mac("02:00:00:00:00:03")).unwrap(),
        ];
        assert!(
            !ips.contains(&ip(192, 168, 124, 9)),
            "gateway .9 must never be allocated"
        );
    }

    #[test]
    fn gateway_adjacent_to_pool_end_never_allocated() {
        // Gateway sits just above the pool end.
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 13),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        let ips = [
            ipam.allocate(mac("02:00:00:00:00:01")).unwrap(),
            ipam.allocate(mac("02:00:00:00:00:02")).unwrap(),
            ipam.allocate(mac("02:00:00:00:00:03")).unwrap(),
        ];
        assert!(
            !ips.contains(&ip(192, 168, 124, 13)),
            "gateway .13 must never be allocated"
        );
    }

    // Edge cases.

    #[test]
    fn two_macs_never_get_same_ip() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 14)),
        ));
        let mut seen = std::collections::HashSet::new();
        for i in 1..=5 {
            let mac = format!("02:00:00:00:00:{i:02x}");
            let allocated = ipam.allocate(mac.parse().unwrap()).unwrap();
            assert!(seen.insert(allocated), "duplicate IP {allocated} handed out");
        }
    }

    #[test]
    fn single_address_pool() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 10)),
        ));
        assert_eq!(ipam.allocate(mac("02:00:00:00:00:01")).unwrap(), ip(192, 168, 124, 10));
        assert_eq!(ipam.allocate(mac("02:00:00:00:00:02")), Err(IpamError::PoolExhausted));
        ipam.release(mac("02:00:00:00:00:01")).unwrap();
        assert_eq!(ipam.allocate(mac("02:00:00:00:00:03")).unwrap(), ip(192, 168, 124, 10));
    }

    #[test]
    fn full_pool_release_one_reallocate() {
        let mut ipam = Ipam::new(lab_network(
            ip(192, 168, 124, 1),
            pool(ip(192, 168, 124, 10), ip(192, 168, 124, 12)),
        ));
        ipam.allocate(mac("02:00:00:00:00:01")).unwrap(); // .10
        ipam.allocate(mac("02:00:00:00:00:02")).unwrap(); // .11
        ipam.allocate(mac("02:00:00:00:00:03")).unwrap(); // .12
        ipam.release(mac("02:00:00:00:00:02")).unwrap(); // free .11
        let reallocated = ipam.allocate(mac("02:00:00:00:00:04")).unwrap();
        assert_eq!(
            reallocated,
            ip(192, 168, 124, 11),
            "lowest free address is the released .11"
        );
    }
}
