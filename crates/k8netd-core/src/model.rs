//! Domain model types for k8netd (spec REQ-002, REQ-003, REQ-004, REQ-010).
//!
//! TASK-002 (test-first): the `tests` module below defines the contract for
//! the domain types. The types do not exist yet, so the tests fail to compile
//! (red phase). TASK-003 implements the types in this file to make the tests
//! pass; the tests module stays at the bottom of the file per Rust convention.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Error type for domain model construction and parsing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    /// A required name was empty or whitespace-only.
    EmptyName,
    /// An IPv4 CIDR string could not be parsed or was invalid.
    InvalidCidr(String),
    /// A gateway address was unparseable or outside its network.
    InvalidGateway(String),
    /// An IP pool was invalid (reversed bounds, outside CIDR, or containing the gateway).
    InvalidPool(String),
    /// A MAC address string could not be parsed.
    InvalidMac(String),
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ModelError::EmptyName => write!(f, "name must not be empty or whitespace"),
            ModelError::InvalidCidr(s) => write!(f, "invalid IPv4 CIDR: {s}"),
            ModelError::InvalidGateway(s) => write!(f, "invalid gateway address: {s}"),
            ModelError::InvalidPool(s) => write!(f, "invalid IP pool: {s}"),
            ModelError::InvalidMac(s) => write!(f, "invalid MAC address: {s}"),
        }
    }
}

impl std::error::Error for ModelError {}

/// An IPv4 CIDR block: a network address and prefix length (spec REQ-002).
///
/// Parsed from `"a.b.c.d/pp"`; the address must be a clean network address
/// (no host bits set) and the prefix must be at most 32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Cidr {
    /// The network address (host bits cleared).
    pub addr: Ipv4Addr,
    /// The prefix length in bits (0..=32).
    pub prefix: u8,
}

impl Ipv4Cidr {
    /// Returns the 32-bit network mask for the prefix.
    fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }
}

impl FromStr for Ipv4Cidr {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| ModelError::InvalidCidr(s.to_string()))?;
        let addr: Ipv4Addr = addr_str.parse().map_err(|_| ModelError::InvalidCidr(s.to_string()))?;
        let prefix: u8 = prefix_str.parse().map_err(|_| ModelError::InvalidCidr(s.to_string()))?;
        if prefix > 32 {
            return Err(ModelError::InvalidCidr(s.to_string()));
        }
        let cidr = Ipv4Cidr { addr, prefix };
        if u32::from(addr) & cidr.mask() != u32::from(addr) {
            return Err(ModelError::InvalidCidr(s.to_string()));
        }
        Ok(cidr)
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// An inclusive range of IPv4 addresses available for allocation (spec REQ-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpPool {
    /// The first address in the pool.
    pub start: Ipv4Addr,
    /// The last address in the pool.
    pub end: Ipv4Addr,
}

impl IpPool {
    /// Creates a pool; rejects reversed bounds where `start` is greater than `end`.
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self, ModelError> {
        if u32::from(start) > u32::from(end) {
            return Err(ModelError::InvalidPool(format!("start {start} is after end {end}")));
        }
        Ok(IpPool { start, end })
    }
}

/// An L2 network segment: name, CIDR, gateway, and allocation pool (spec REQ-002).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    /// The network name.
    pub name: String,
    /// The IPv4 CIDR block.
    pub cidr: Ipv4Cidr,
    /// The gateway address (inside the CIDR, outside the pool).
    pub gateway: Ipv4Addr,
    /// The allocation pool (inside the CIDR, excluding the gateway).
    pub pool: IpPool,
}

impl Network {
    /// Creates a network, validating the name, CIDR, gateway, and pool.
    pub fn new(name: &str, cidr: &str, gateway: &str, pool: IpPool) -> Result<Self, ModelError> {
        if name.trim().is_empty() {
            return Err(ModelError::EmptyName);
        }
        let cidr: Ipv4Cidr = cidr.parse()?;
        let gateway: Ipv4Addr = gateway
            .parse()
            .map_err(|_| ModelError::InvalidGateway(gateway.to_string()))?;
        if u32::from(gateway) & cidr.mask() != u32::from(cidr.addr) {
            return Err(ModelError::InvalidGateway(format!("{gateway} is outside {cidr}")));
        }
        if u32::from(pool.start) & cidr.mask() != u32::from(cidr.addr)
            || u32::from(pool.end) & cidr.mask() != u32::from(cidr.addr)
        {
            return Err(ModelError::InvalidPool(format!(
                "pool {}-{} is outside {cidr}",
                pool.start, pool.end
            )));
        }
        let gw = u32::from(gateway);
        if (u32::from(pool.start)..=u32::from(pool.end)).contains(&gw) {
            return Err(ModelError::InvalidPool(format!(
                "pool {}-{} contains gateway {gateway}",
                pool.start, pool.end
            )));
        }
        Ok(Network {
            name: name.to_string(),
            cidr,
            gateway,
            pool,
        })
    }
}

/// A 48-bit Ethernet MAC address (spec REQ-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr([u8; 6]);

impl FromStr for MacAddr {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return Err(ModelError::InvalidMac(s.to_string()));
        }
        let mut octets = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            if part.len() != 2 {
                return Err(ModelError::InvalidMac(s.to_string()));
            }
            octets[i] = u8::from_str_radix(part, 16).map_err(|_| ModelError::InvalidMac(s.to_string()))?;
        }
        Ok(MacAddr(octets))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// A vhost-user backend endpoint that can be attached to a network (spec REQ-003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    /// The port name.
    pub name: String,
    /// The listening Unix socket path.
    pub socket_path: PathBuf,
    /// The attached network name, if any.
    pub network: Option<String>,
    /// The attached MAC address, if any.
    pub mac: Option<MacAddr>,
    /// The attached IP address, if any.
    pub ip: Option<Ipv4Addr>,
}

impl Port {
    /// Creates a detached port; rejects empty or whitespace-only names.
    pub fn new(name: &str, socket_path: impl Into<PathBuf>) -> Result<Self, ModelError> {
        if name.trim().is_empty() {
            return Err(ModelError::EmptyName);
        }
        Ok(Port {
            name: name.to_string(),
            socket_path: socket_path.into(),
            network: None,
            mac: None,
            ip: None,
        })
    }

    /// Attaches the port to a network with a MAC and IP binding.
    pub fn attach(&mut self, network: &str, mac: MacAddr, ip: Ipv4Addr) {
        self.network = Some(network.to_string());
        self.mac = Some(mac);
        self.ip = Some(ip);
    }

    /// Detaches the port; the socket path is kept alive.
    pub fn detach(&mut self) {
        self.network = None;
        self.mac = None;
        self.ip = None;
    }
}

/// An IPAM allocation record binding a MAC address to an IP on a network (spec REQ-004).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allocation {
    /// The network name.
    pub network: String,
    /// The bound MAC address.
    pub mac: MacAddr,
    /// The allocated IP address.
    pub ip: Ipv4Addr,
}

/// A DHCP lease record (spec REQ-005).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpLease {
    /// The leased MAC address.
    pub mac: MacAddr,
    /// The leased IP address.
    pub ip: Ipv4Addr,
    /// The lease duration in seconds.
    pub lease_seconds: u64,
}

/// The persisted daemon state: networks, ports, allocations, and leases (spec REQ-010).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct State {
    /// Networks keyed by name.
    pub networks: HashMap<String, Network>,
    /// Ports keyed by name.
    pub ports: HashMap<String, Port>,
    /// IPAM allocation records.
    pub allocations: Vec<Allocation>,
    /// DHCP lease records.
    pub leases: Vec<DhcpLease>,
}

#[cfg(test)]
mod tests {
    // Expected API — implemented by TASK-003 to satisfy these tests:
    //
    // pub struct Ipv4Cidr { addr: Ipv4Addr, prefix: u8 }
    //   - FromStr for "a.b.c.d/pp"; rejects unparseable input, prefix > 32,
    //     and host bits set in the address (e.g. "192.168.124.1/24")
    //   - Display as "a.b.c.d/pp"
    //   - Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug
    //
    // pub struct IpPool { start: Ipv4Addr, end: Ipv4Addr }
    //   - IpPool::new(start, end) -> Result<IpPool, ModelError>; rejects
    //     start > end
    //   - Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug
    //
    // pub struct Network { name: String, cidr: Ipv4Cidr, gateway: Ipv4Addr, pool: IpPool }
    //   - Network::new(name: &str, cidr: &str, gateway: &str, pool: IpPool)
    //     -> Result<Network, ModelError>; rejects empty/whitespace name,
    //     unparseable cidr, host bits in cidr, prefix > 32, unparseable
    //     gateway, gateway outside the cidr, pool outside the cidr, and a
    //     pool that contains the gateway address
    //   - Serialize, Deserialize, PartialEq, Eq, Clone, Debug
    //
    // pub struct MacAddr([u8; 6])
    //   - FromStr for "aa:bb:cc:dd:ee:ff"; rejects wrong length, non-hex
    //     octets, and empty input
    //   - Display as lowercase colon-separated hex
    //   - Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy, Debug
    //
    // pub struct Port { name: String, socket_path: PathBuf,
    //                   network: Option<String>, mac: Option<MacAddr>,
    //                   ip: Option<Ipv4Addr> }
    //   - Port::new(name: &str, socket_path: impl Into<PathBuf>)
    //     -> Result<Port, ModelError>; rejects empty/whitespace name
    //   - Port::attach(&mut self, network: &str, mac: MacAddr, ip: Ipv4Addr)
    //   - Port::detach(&mut self)
    //   - Serialize, Deserialize, PartialEq, Eq, Clone, Debug
    //
    // pub struct Allocation { network: String, mac: MacAddr, ip: Ipv4Addr }
    //   - Serialize, Deserialize, PartialEq, Eq, Clone, Debug
    //
    // pub struct DhcpLease { mac: MacAddr, ip: Ipv4Addr, lease_seconds: u64 }
    //   - Serialize, Deserialize, PartialEq, Eq, Clone, Debug
    //
    // pub struct State {
    //     networks: HashMap<String, Network>,
    //     ports: HashMap<String, Port>,
    //     allocations: Vec<Allocation>,
    //     leases: Vec<DhcpLease>,
    // }
    //   - Default (empty collections)
    //   - Serialize, Deserialize, PartialEq, Eq, Clone, Debug

    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    fn lab_pool() -> IpPool {
        IpPool::new(ip(192, 168, 124, 10), ip(192, 168, 124, 200)).unwrap()
    }

    // REQ-1: Network construction and validation.

    #[test]
    fn network_valid_construction() {
        let n = Network::new("lab", "192.168.124.0/24", "192.168.124.1", lab_pool()).expect("valid network");
        assert_eq!(n.name, "lab");
        assert_eq!(n.cidr, "192.168.124.0/24".parse::<Ipv4Cidr>().unwrap());
        assert_eq!(n.gateway, ip(192, 168, 124, 1));
        assert_eq!(n.pool.start, ip(192, 168, 124, 10));
        assert_eq!(n.pool.end, ip(192, 168, 124, 200));
    }

    #[test]
    fn network_rejects_empty_name() {
        assert!(Network::new("", "192.168.124.0/24", "192.168.124.1", lab_pool()).is_err());
    }

    #[test]
    fn network_rejects_whitespace_name() {
        assert!(Network::new("   ", "192.168.124.0/24", "192.168.124.1", lab_pool()).is_err());
    }

    #[test]
    fn network_rejects_unparseable_cidr() {
        assert!(Network::new("lab", "not-a-cidr", "192.168.124.1", lab_pool()).is_err());
    }

    #[test]
    fn network_rejects_cidr_with_host_bits() {
        // 192.168.124.1/24 has host bits set; the network address must be clean.
        assert!(Network::new("lab", "192.168.124.1/24", "192.168.124.1", lab_pool()).is_err());
    }

    #[test]
    fn network_rejects_prefix_out_of_range() {
        assert!(Network::new("lab", "192.168.124.0/33", "192.168.124.1", lab_pool()).is_err());
    }

    #[test]
    fn network_rejects_unparseable_gateway() {
        assert!(Network::new("lab", "192.168.124.0/24", "not-an-ip", lab_pool()).is_err());
    }

    #[test]
    fn network_rejects_gateway_outside_cidr() {
        assert!(Network::new("lab", "192.168.124.0/24", "10.0.0.1", lab_pool()).is_err());
    }

    #[test]
    fn network_rejects_pool_outside_cidr() {
        let outside = IpPool::new(ip(10, 0, 0, 1), ip(10, 0, 0, 10)).unwrap();
        assert!(Network::new("lab", "192.168.124.0/24", "192.168.124.1", outside).is_err());
    }

    #[test]
    fn network_rejects_pool_overlapping_gateway() {
        // The pool contains the gateway address 192.168.124.1.
        let overlapping = IpPool::new(ip(192, 168, 124, 1), ip(192, 168, 124, 10)).unwrap();
        assert!(Network::new("lab", "192.168.124.0/24", "192.168.124.1", overlapping).is_err());
    }

    #[test]
    fn ip_pool_rejects_reversed_bounds() {
        assert!(IpPool::new(ip(192, 168, 124, 200), ip(192, 168, 124, 10)).is_err());
    }

    #[test]
    fn ip_pool_accepts_single_address() {
        let p = IpPool::new(ip(192, 168, 124, 10), ip(192, 168, 124, 10)).unwrap();
        assert_eq!(p.start, p.end);
    }

    #[test]
    fn ipv4_cidr_rejects_host_bits() {
        assert!("192.168.124.1/24".parse::<Ipv4Cidr>().is_err());
    }

    #[test]
    fn ipv4_cidr_parses_clean_network() {
        let c: Ipv4Cidr = "192.168.124.0/24".parse().unwrap();
        assert_eq!(c.to_string(), "192.168.124.0/24");
    }

    // REQ-2: Port state transitions (created -> attached -> detached).

    #[test]
    fn port_created_is_detached() {
        let p = Port::new("vm1", "/run/user/1000/k8snet/vm1.sock").unwrap();
        assert_eq!(p.name, "vm1");
        assert_eq!(p.socket_path, PathBuf::from("/run/user/1000/k8snet/vm1.sock"));
        assert_eq!(p.network, None);
        assert_eq!(p.mac, None);
        assert_eq!(p.ip, None);
    }

    #[test]
    fn port_rejects_empty_name() {
        assert!(Port::new("", "/run/user/1000/k8snet/vm1.sock").is_err());
    }

    #[test]
    fn port_rejects_whitespace_name() {
        assert!(Port::new("   ", "/run/user/1000/k8snet/vm1.sock").is_err());
    }

    #[test]
    fn port_attach_sets_attachment() {
        let mut p = Port::new("vm1", "/run/user/1000/k8snet/vm1.sock").unwrap();
        p.attach("lab", mac("02:00:00:00:00:01"), ip(192, 168, 124, 10));
        assert_eq!(p.network.as_deref(), Some("lab"));
        assert_eq!(p.mac, Some(mac("02:00:00:00:00:01")));
        assert_eq!(p.ip, Some(ip(192, 168, 124, 10)));
    }

    #[test]
    fn port_detach_clears_attachment_keeps_socket() {
        let mut p = Port::new("vm1", "/run/user/1000/k8snet/vm1.sock").unwrap();
        p.attach("lab", mac("02:00:00:00:00:01"), ip(192, 168, 124, 10));
        p.detach();
        assert_eq!(p.network, None);
        assert_eq!(p.mac, None);
        assert_eq!(p.ip, None);
        assert_eq!(p.socket_path, PathBuf::from("/run/user/1000/k8snet/vm1.sock"));
    }

    #[test]
    fn port_reattach_after_detach() {
        let mut p = Port::new("vm1", "/run/user/1000/k8snet/vm1.sock").unwrap();
        p.attach("lab", mac("02:00:00:00:00:01"), ip(192, 168, 124, 10));
        p.detach();
        p.attach("other", mac("02:00:00:00:00:02"), ip(192, 168, 124, 11));
        assert_eq!(p.network.as_deref(), Some("other"));
        assert_eq!(p.mac, Some(mac("02:00:00:00:00:02")));
        assert_eq!(p.ip, Some(ip(192, 168, 124, 11)));
    }

    // MAC address parsing (edge cases).

    #[test]
    fn mac_parses_valid() {
        let m: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        assert_eq!(m.to_string(), "02:00:00:00:00:01");
    }

    #[test]
    fn mac_rejects_too_short() {
        assert!("02:00:00:00:00".parse::<MacAddr>().is_err());
    }

    #[test]
    fn mac_rejects_too_long() {
        assert!("02:00:00:00:00:01:02".parse::<MacAddr>().is_err());
    }

    #[test]
    fn mac_rejects_non_hex() {
        assert!("zz:00:00:00:00:01".parse::<MacAddr>().is_err());
    }

    #[test]
    fn mac_rejects_empty() {
        assert!("".parse::<MacAddr>().is_err());
    }

    #[test]
    fn mac_display_round_trip() {
        let m: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        let again: MacAddr = m.to_string().parse().unwrap();
        assert_eq!(m, again);
    }

    // REQ-3: IPAM allocation records (ip <-> mac binding).

    #[test]
    fn allocation_binds_ip_to_mac() {
        let a = Allocation {
            network: "lab".to_string(),
            mac: mac("02:00:00:00:00:01"),
            ip: ip(192, 168, 124, 10),
        };
        assert_eq!(a.network, "lab");
        assert_eq!(a.mac, mac("02:00:00:00:00:01"));
        assert_eq!(a.ip, ip(192, 168, 124, 10));
    }

    #[test]
    fn allocation_serde_round_trip() {
        let a = Allocation {
            network: "lab".to_string(),
            mac: mac("02:00:00:00:00:01"),
            ip: ip(192, 168, 124, 10),
        };
        let json = serde_json::to_string(&a).unwrap();
        let restored: Allocation = serde_json::from_str(&json).unwrap();
        assert_eq!(a, restored);
    }

    // REQ-4: DHCP lease records.

    #[test]
    fn dhcp_lease_records_fields() {
        let l = DhcpLease {
            mac: mac("02:00:00:00:00:01"),
            ip: ip(192, 168, 124, 10),
            lease_seconds: 3600,
        };
        assert_eq!(l.mac, mac("02:00:00:00:00:01"));
        assert_eq!(l.ip, ip(192, 168, 124, 10));
        assert_eq!(l.lease_seconds, 3600);
    }

    #[test]
    fn dhcp_lease_serde_round_trip() {
        let l = DhcpLease {
            mac: mac("02:00:00:00:00:01"),
            ip: ip(192, 168, 124, 10),
            lease_seconds: 3600,
        };
        let json = serde_json::to_string(&l).unwrap();
        let restored: DhcpLease = serde_json::from_str(&json).unwrap();
        assert_eq!(l, restored);
    }

    // REQ-5: persisted State structure — serde round-trip.

    #[test]
    fn state_round_trip_empty() {
        let state = State::default();
        let json = serde_json::to_string(&state).unwrap();
        let restored: State = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }

    #[test]
    fn state_round_trip_populated() {
        let network = Network::new("lab", "192.168.124.0/24", "192.168.124.1", lab_pool()).unwrap();
        let mut port = Port::new("vm1", "/run/user/1000/k8snet/vm1.sock").unwrap();
        port.attach("lab", mac("02:00:00:00:00:01"), ip(192, 168, 124, 10));

        let mut state = State::default();
        state.networks.insert("lab".to_string(), network);
        state.ports.insert("vm1".to_string(), port);
        state.allocations.push(Allocation {
            network: "lab".to_string(),
            mac: mac("02:00:00:00:00:01"),
            ip: ip(192, 168, 124, 10),
        });
        state.leases.push(DhcpLease {
            mac: mac("02:00:00:00:00:01"),
            ip: ip(192, 168, 124, 10),
            lease_seconds: 3600,
        });

        let json = serde_json::to_string(&state).unwrap();
        let restored: State = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }
}
