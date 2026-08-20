//! Domain model types for k8netd (spec REQ-002, REQ-003, REQ-004, REQ-010).
//!
//! TASK-002 (test-first): the `tests` module below defines the contract for
//! the domain types. The types do not exist yet, so the tests fail to compile
//! (red phase). TASK-003 implements the types in this file to make the tests
//! pass; the tests module stays at the bottom of the file per Rust convention.

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
