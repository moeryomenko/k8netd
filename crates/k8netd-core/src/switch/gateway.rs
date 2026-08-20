//! Gateway function: per-network ARP responder + per-port egress (spec
//! REQ-007, VC-02, plan TASK-012, TEST-FIRST).
//!
//! TASK-012 (test-first): the `tests` module below defines the contract for
//! the gateway function. The function does not exist yet, so the tests fail
//! to compile (red phase). TASK-013 implements it in this file to make the
//! tests pass; the tests module stays at the bottom of the file per Rust
//! convention.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::model::{Ipv4Cidr, Network};
use crate::switch::frame::ParsedFrame;
use crate::switch::mac_table::PortId;

/// Ethernet ethertype: ARP (RFC 826).
const ETHERTYPE_ARP: u16 = 0x0806;
/// Ethernet ethertype: IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// Length of the untagged ethernet header in bytes.
const ETH_HEADER_LEN: usize = 14;
/// Length of a standard IPv4-over-Ethernet ARP payload in bytes.
const ARP_LEN: usize = 28;
/// Minimum length of an IPv4 header (IHL 5, no options) in bytes.
const IPV4_MIN_HEADER_LEN: usize = 20;
/// Minimum IPv4 IHL (header length, in 32-bit words).
const IPV4_MIN_IHL: usize = 5;
/// Size of one IPv4 IHL unit in bytes.
const IPV4_IHL_UNIT: usize = 4;

/// The gateway function: per-network ARP responder and per-port egress
/// classifier (spec REQ-007).
///
/// The gateway is per-network: each configured [`Network`] contributes its
/// gateway address (for ARP) and its CIDR (for local/non-local
/// classification), and each attached port is bound to exactly one network
/// name. `handle_frame` is stateless per frame (`&self`, no I/O): it drives
/// the existing [`ParsedFrame::parse`] and the network configuration. It
/// never produces a frame for any port other than the ingress: [`Wan`]
/// egress is always the ingress port's own passt WAN output and
/// [`ArpReply`] is delivered to the ingress port. There is no shared WAN
/// output and no inbound L3 routing path (spec REQ-007: "No inbound L3
/// routing"; per-VM passt handles inbound deterministically).
#[derive(Debug)]
pub struct Gateway {
    /// Configured networks keyed by name.
    networks: HashMap<String, Network>,
    /// Attached ports keyed by handle, mapped to their network name.
    ports: HashMap<PortId, String>,
}

impl Gateway {
    /// Creates an empty gateway with no networks and no ports.
    pub fn new() -> Gateway {
        Gateway {
            networks: HashMap::new(),
            ports: HashMap::new(),
        }
    }

    /// Adds `network` to the gateway, keyed by its name.
    ///
    /// Re-adding a network with the same name replaces the existing entry.
    pub fn add_network(&mut self, network: &Network) {
        self.networks.insert(network.name.clone(), network.clone());
    }

    /// Removes the network named `name`; returns true when it was configured.
    pub fn remove_network(&mut self, name: &str) -> bool {
        self.networks.remove(name).is_some()
    }

    /// Attaches `port` to the network named `network`.
    ///
    /// Re-attaching an existing port replaces its network binding.
    pub fn add_port(&mut self, port: PortId, network: &str) {
        self.ports.insert(port, network.to_string());
    }

    /// Detaches `port`; returns true when the port was attached.
    pub fn remove_port(&mut self, port: PortId) -> bool {
        self.ports.remove(&port).is_some()
    }

    /// Classifies `frame` arriving at `ingress`, returning the gateway action.
    ///
    /// The ingress port's network (from the port map) selects both the
    /// gateway address (ARP) and the CIDR (local/non-local classification).
    /// Frames at unattached ports, at ports whose network is not configured,
    /// and unparseable frames are [`L2`]: the switch's L2 behavior applies
    /// and the gateway never touches the WAN.
    pub fn handle_frame<'a>(&self, ingress: PortId, frame: &'a [u8]) -> GatewayAction<'a> {
        let Some(network_name) = self.ports.get(&ingress) else {
            return GatewayAction::L2;
        };
        let Some(network) = self.networks.get(network_name) else {
            return GatewayAction::L2;
        };
        let Ok(parsed) = ParsedFrame::parse(frame) else {
            return GatewayAction::L2;
        };
        match parsed.ethertype {
            ETHERTYPE_ARP => arp_response(network, &parsed),
            ETHERTYPE_IPV4 => ipv4_egress(network, &parsed, frame),
            _ => GatewayAction::L2,
        }
    }
}

impl Default for Gateway {
    fn default() -> Self {
        Self::new()
    }
}

/// Answers an ARP request for `network`'s gateway address.
///
/// Exactly one frame class is answered: an ARP request (op 1) of a standard
/// IPv4-over-Ethernet ARP (htype 1, ptype 0x0800, hlen 6, plen 4, at least
/// 28 payload bytes) whose target protocol address equals the network's
/// gateway. The L2 destination of the request (broadcast or unicast) does
/// not matter. The reply is unicast to the requester; ARP replies (op 2)
/// and requests for any other address are not answered.
fn arp_response<'p>(network: &Network, parsed: &ParsedFrame<'p>) -> GatewayAction<'p> {
    let payload = parsed.payload;
    if !is_ipv4_over_ethernet_arp_request(payload) {
        return GatewayAction::L2;
    }
    let tpa = Ipv4Addr::from([payload[24], payload[25], payload[26], payload[27]]);
    if tpa != network.gateway {
        return GatewayAction::L2;
    }
    GatewayAction::ArpReply(build_arp_reply(payload, network.gateway))
}

/// Classifies an IPv4 frame as local or non-local for `network`.
///
/// A destination IP outside the network's CIDR is egressed byte-identical to
/// the ingress port's own passt WAN output ([`Wan`]); a destination inside
/// the CIDR — including the gateway IP itself — is [`L2`], so VM-to-VM and
/// VM-to-gateway traffic bypasses the WAN. An invalid IPv4 header (payload
/// shorter than IHL*4, IHL < 5, or IP version != 4) is dropped for egress:
/// [`L2`].
fn ipv4_egress<'p>(network: &Network, parsed: &ParsedFrame<'p>, frame: &'p [u8]) -> GatewayAction<'p> {
    let payload = parsed.payload;
    if !is_valid_ipv4_header(payload) {
        return GatewayAction::L2;
    }
    let dst = Ipv4Addr::from([payload[16], payload[17], payload[18], payload[19]]);
    if in_cidr(dst, &network.cidr) {
        GatewayAction::L2
    } else {
        GatewayAction::Wan(frame)
    }
}

/// The gateway action for one ingress frame (spec REQ-007).
///
/// The action names the dataplane output, never a port: [`Wan`] is always
/// the ingress port's own passt WAN output and [`ArpReply`] is delivered to
/// the ingress port (the requester).
#[derive(Debug)]
pub enum GatewayAction<'a> {
    /// L2 only: no gateway action; the switch forwards/floods as usual.
    L2,
    /// Egress: write the frame (byte-identical to the input) to the ingress
    /// port's own passt WAN output.
    Wan(&'a [u8]),
    /// ARP reply: deliver the constructed reply frame to the ingress port
    /// (the requester).
    ArpReply(Vec<u8>),
}

/// Returns true when `payload` is a standard IPv4-over-Ethernet ARP request:
/// at least 28 bytes, htype 1, ptype 0x0800, hlen 6, plen 4, op 1.
fn is_ipv4_over_ethernet_arp_request(payload: &[u8]) -> bool {
    payload.len() >= ARP_LEN
        && u16::from_be_bytes([payload[0], payload[1]]) == 1 // htype: Ethernet
        && u16::from_be_bytes([payload[2], payload[3]]) == 0x0800 // ptype: IPv4
        && payload[4] == 6 // hlen
        && payload[5] == 4 // plen
        && u16::from_be_bytes([payload[6], payload[7]]) == 1 // op: request
}

/// Returns true when `payload` holds a valid IPv4 header: at least IHL*4
/// bytes, IHL >= 5, and IP version 4.
fn is_valid_ipv4_header(payload: &[u8]) -> bool {
    if payload.len() < IPV4_MIN_HEADER_LEN {
        return false;
    }
    let first = payload[0];
    let version = first >> 4;
    let ihl = (first & 0x0f) as usize;
    version == 4 && ihl >= IPV4_MIN_IHL && payload.len() >= ihl * IPV4_IHL_UNIT
}

/// Returns true when `ip` is inside `cidr`.
fn in_cidr(ip: Ipv4Addr, cidr: &Ipv4Cidr) -> bool {
    let mask = if cidr.prefix == 0 {
        0
    } else {
        u32::MAX << (32 - cidr.prefix)
    };
    u32::from(ip) & mask == u32::from(cidr.addr)
}

/// Derives the gateway MAC from the gateway IP: 02:00:<o1>:<o2>:<o3>:<o4>
/// (locally administered, stable per gateway IP, unique per address).
fn gateway_mac(gateway: Ipv4Addr) -> [u8; 6] {
    let octets = gateway.octets();
    [0x02, 0x00, octets[0], octets[1], octets[2], octets[3]]
}

/// Builds the 42-byte ARP reply to a 28-byte ARP request payload: op 2,
/// unicast to the requester (dst = the request's sha), src = sha = the
/// gateway MAC, spa = the gateway IP, tha = the requester's MAC, tpa = the
/// requester's IP.
fn build_arp_reply(request: &[u8], gateway: Ipv4Addr) -> Vec<u8> {
    let gw_mac = gateway_mac(gateway);
    let mut reply = Vec::with_capacity(ETH_HEADER_LEN + ARP_LEN);
    reply.extend_from_slice(&request[8..14]); // dst MAC: the request's sha
    reply.extend_from_slice(&gw_mac); // src MAC: the gateway
    reply.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    reply.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
    reply.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
    reply.push(6); // hlen
    reply.push(4); // plen
    reply.extend_from_slice(&2u16.to_be_bytes()); // op: reply
    reply.extend_from_slice(&gw_mac); // sha: the gateway
    reply.extend_from_slice(&gateway.octets()); // spa: the gateway IP
    reply.extend_from_slice(&request[8..14]); // tha: the requester's MAC
    reply.extend_from_slice(&request[14..18]); // tpa: the requester's IP
    reply
}

#[cfg(test)]
mod tests {
    // Expected API — implemented by TASK-013 to satisfy these tests:
    //
    // #[derive(Debug)]
    // pub struct Gateway { ... }
    //   - holds the per-network configuration (the `Network` objects — the
    //     same ones the `Ipam` holds; the TASK-031 wiring passes the
    //     state's networks) and the port -> network-name attachment map
    //
    // impl Gateway {
    //     pub fn new() -> Gateway
    //     pub fn add_network(&mut self, network: &Network) // re-adding replaces
    //     pub fn remove_network(&mut self, name: &str) -> bool // true if present
    //     pub fn add_port(&mut self, port: PortId, network: &str) // re-adding replaces
    //     pub fn remove_port(&mut self, port: PortId) -> bool // true if live
    //     pub fn handle_frame<'a>(&self, ingress: PortId, frame: &'a [u8]) -> GatewayAction<'a>
    // }
    //
    // #[derive(Debug)]
    // pub enum GatewayAction<'a> {
    //     /// L2 only: no gateway action; the switch forwards/floods as usual.
    //     L2,
    //     /// Egress: write the frame (byte-identical to the input) to the
    //     /// ingress port's own passt WAN output.
    //     Wan(&'a [u8]),
    //     /// ARP reply: deliver the constructed reply frame to the ingress
    //     /// port (the requester).
    //     ArpReply(Vec<u8>),
    // }
    //
    // The gateway is synchronous, has no I/O, and is stateless per frame
    // (`&self`): it drives the existing `ParsedFrame::parse` (no re-parsing
    // of the ethernet header) plus the `Network` configuration. It never
    // produces a frame for a port other than the ingress: `Wan` is always
    // the ingress port's own WAN and `ArpReply` is delivered to the ingress
    // port. There is no shared WAN output and no inbound L3 routing path in
    // the API (spec REQ-007: "No inbound L3 routing"; per-VM passt handles
    // inbound deterministically).
    //
    // Behavior pins (decided here):
    //
    // 1. The gateway is per-network: the ingress port's network (from the
    //    port map) selects both the gateway address (ARP) and the CIDR
    //    (local/non-local classification). A frame at a port whose network
    //    the gateway has not been given is `L2` (no configuration to act
    //    on; the switch's L2 behavior applies).
    // 2. ARP response: exactly one frame class is answered — an ARP request
    //    (ethertype 0x0806, op 1) whose target protocol address (tpa)
    //    equals the ingress network's gateway. The ARP must be a standard
    //    IPv4-over-Ethernet ARP (htype 1, ptype 0x0800, hlen 6, plen 4,
    //    payload at least 28 bytes). ARP replies (op 2) are never
    //    answered. The L2 destination of the request (broadcast or
    //    unicast) does not matter.
    // 3. The reply is a standard ARP reply (op 2), unicast to the
    //    requester: dst MAC = the request's sha, src MAC = the gateway MAC,
    //    sha = the gateway MAC, spa = the gateway IP, tha = the requester's
    //    MAC, tpa = the requester's IP.
    // 4. The gateway MAC is derived from the gateway IP:
    //    02:00:<o1>:<o2>:<o3>:<o4> (locally administered, stable per
    //    gateway IP, unique per address). Example: 192.168.124.1 ->
    //    02:00:c0:a8:7c:01.
    // 5. Per-port egress: an IPv4 frame (ethertype 0x0800) whose
    //    destination IP (offset 16 of the IP header) is outside the ingress
    //    network's CIDR is delivered byte-identical to the ingress port's
    //    own passt WAN output (`Wan`). The frame is never modified and
    //    never sent to any other port's WAN.
    // 6. Local frames: an IPv4 frame whose destination IP is inside the
    //    CIDR — including the gateway IP itself — is `L2`: the switch
    //    handles it (VM-to-VM and VM-to-gateway traffic bypasses the WAN).
    // 7. Invalid IPv4 header: a 0x0800 frame whose IP header is invalid
    //    (payload shorter than IHL*4, IHL < 5, or IP version != 4) is `L2`
    //    (dropped for egress purposes, never routed to the WAN).
    // 8. Unattached port: a frame at a port that is not in the port map is
    //    `L2` (dropped).
    // 9. Frames of any other ethertype (neither 0x0806 nor 0x0800) are
    //    `L2`; the switch is the only handler.

    use super::*;
    use crate::model::{IpPool, Network};
    use crate::switch::mac_table::PortId;
    use std::net::Ipv4Addr;

    const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const MAC_D: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x09];
    const BCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    const ZERO: [u8; 6] = [0x00; 6];
    /// The derived gateway MAC for the lab gateway 192.168.124.1 (pin 4).
    const GW_MAC_LAB: [u8; 6] = [0x02, 0x00, 0xc0, 0xa8, 0x7c, 0x01];
    const ARP: u16 = 0x0806;
    const IPV4: u16 = 0x0800;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    /// Builds an untagged ethernet frame from header parts and a payload.
    fn eth_frame(dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(dst);
        frame.extend_from_slice(src);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Builds the 28-byte ARP payload for an IPv4-over-Ethernet ARP.
    fn arp_payload(op: u16, sha: &[u8; 6], spa: Ipv4Addr, tha: &[u8; 6], tpa: Ipv4Addr) -> Vec<u8> {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
        p.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
        p.push(6); // hlen
        p.push(4); // plen
        p.extend_from_slice(&op.to_be_bytes());
        p.extend_from_slice(sha);
        p.extend_from_slice(&spa.octets());
        p.extend_from_slice(tha);
        p.extend_from_slice(&tpa.octets());
        p
    }

    /// Builds a full ethernet frame carrying an ARP payload.
    fn arp_frame(
        dst: &[u8; 6],
        src: &[u8; 6],
        op: u16,
        sha: &[u8; 6],
        spa: Ipv4Addr,
        tha: &[u8; 6],
        tpa: Ipv4Addr,
    ) -> Vec<u8> {
        eth_frame(dst, src, ARP, &arp_payload(op, sha, spa, tha, tpa))
    }

    /// Builds a minimal 20-byte IPv4 header (no options, TTL 64, UDP).
    fn ipv4_header(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut h = Vec::with_capacity(20);
        h.push(0x45); // version 4, IHL 5
        h.push(0x00); // DSCP/ECN
        h.extend_from_slice(&20u16.to_be_bytes()); // total length
        h.extend_from_slice(&0u16.to_be_bytes()); // identification
        h.extend_from_slice(&0x4000u16.to_be_bytes()); // flags DF, frag offset 0
        h.push(64); // TTL
        h.push(17); // protocol: UDP
        h.extend_from_slice(&0u16.to_be_bytes()); // header checksum (not verified)
        h.extend_from_slice(&src.octets());
        h.extend_from_slice(&dst.octets());
        h
    }

    /// Builds a full ethernet frame carrying a minimal IPv4 packet.
    fn ipv4_frame(dst: &[u8; 6], src: &[u8; 6], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
        eth_frame(dst, src, IPV4, &ipv4_header(src_ip, dst_ip))
    }

    fn lab_network() -> Network {
        Network::new(
            "lab",
            "192.168.124.0/24",
            "192.168.124.1",
            IpPool::new(ip(192, 168, 124, 10), ip(192, 168, 124, 200)).unwrap(),
        )
        .unwrap()
    }

    fn staging_network() -> Network {
        Network::new(
            "staging",
            "10.0.0.0/24",
            "10.0.0.1",
            IpPool::new(ip(10, 0, 0, 10), ip(10, 0, 0, 200)).unwrap(),
        )
        .unwrap()
    }

    /// A gateway with ports A and B on "lab" (the only configured network).
    fn lab_gateway() -> Gateway {
        let mut gw = Gateway::new();
        gw.add_network(&lab_network());
        gw.add_port(PortId(1), "lab");
        gw.add_port(PortId(2), "lab");
        gw
    }

    /// A gateway with A and B on "lab" and D on "staging".
    fn two_network_gateway() -> Gateway {
        let mut gw = Gateway::new();
        gw.add_network(&lab_network());
        gw.add_network(&staging_network());
        gw.add_port(PortId(1), "lab");
        gw.add_port(PortId(2), "lab");
        gw.add_port(PortId(9), "staging");
        gw
    }

    // REQ-1: an ARP request for the network gateway is answered with the
    // gateway MAC.

    #[test]
    fn arp_request_for_gateway_answered_with_gateway_mac() {
        let gw = lab_gateway();
        // A (192.168.124.10) asks, unicast to the gateway MAC, for the
        // gateway 192.168.124.1: answered with an ARP reply (op 2) carrying
        // the gateway MAC.
        let frame = arp_frame(
            &GW_MAC_LAB,
            &MAC_A,
            1,
            &MAC_A,
            ip(192, 168, 124, 10),
            &ZERO,
            ip(192, 168, 124, 1),
        );
        let expected = arp_frame(
            &MAC_A, // unicast to the requester
            &GW_MAC_LAB,
            2, // op: reply
            &GW_MAC_LAB,
            ip(192, 168, 124, 1),
            &MAC_A,
            ip(192, 168, 124, 10),
        );
        match gw.handle_frame(PortId(1), &frame) {
            GatewayAction::ArpReply(reply) => assert_eq!(reply, expected),
            other => panic!("expected ArpReply, got {other:?}"),
        }
    }

    // REQ-2: an ARP request for a non-gateway address is NOT answered (the
    // switch floods it like any other L2 frame; that flooding is VC-01).

    #[test]
    fn arp_request_for_peer_address_not_answered() {
        let gw = lab_gateway();
        // A asks for a peer's address (192.168.124.20, inside the CIDR):
        // not the gateway — the gateway stays silent.
        let frame = arp_frame(
            &BCAST,
            &MAC_A,
            1,
            &MAC_A,
            ip(192, 168, 124, 10),
            &ZERO,
            ip(192, 168, 124, 20),
        );
        assert!(matches!(gw.handle_frame(PortId(1), &frame), GatewayAction::L2));
    }

    #[test]
    fn arp_request_for_outside_address_not_answered() {
        let gw = lab_gateway();
        // A asks for an address outside the CIDR (10.0.0.5): not the
        // gateway — L2 only.
        let frame = arp_frame(&BCAST, &MAC_A, 1, &MAC_A, ip(192, 168, 124, 10), &ZERO, ip(10, 0, 0, 5));
        assert!(matches!(gw.handle_frame(PortId(1), &frame), GatewayAction::L2));
    }

    // REQ-3: a non-local IPv4 packet is routed to the ingress port's own
    // WAN output.

    #[test]
    fn non_local_ipv4_routed_to_ingress_own_wan() {
        let gw = lab_gateway();
        // A (192.168.124.10) sends to 8.8.8.8, outside 192.168.124.0/24:
        // egress to A's own passt WAN, byte-identical.
        let frame = ipv4_frame(&GW_MAC_LAB, &MAC_A, ip(192, 168, 124, 10), ip(8, 8, 8, 8));
        match gw.handle_frame(PortId(1), &frame) {
            GatewayAction::Wan(wan) => assert_eq!(wan, &frame),
            other => panic!("expected Wan, got {other:?}"),
        }
    }

    #[test]
    fn non_local_ipv4_on_second_network_routed_to_wan() {
        let gw = two_network_gateway();
        // D (10.0.0.10) on staging sends to 9.9.9.9, outside 10.0.0.0/24:
        // classification uses the ingress network's CIDR, not a fixed one.
        let frame = ipv4_frame(&BCAST, &MAC_D, ip(10, 0, 0, 10), ip(9, 9, 9, 9));
        match gw.handle_frame(PortId(9), &frame) {
            GatewayAction::Wan(wan) => assert_eq!(wan, &frame),
            other => panic!("expected Wan, got {other:?}"),
        }
    }

    // REQ-4: a local IPv4 packet is handled by the L2 switch only and
    // bypasses the WAN entirely.

    #[test]
    fn local_ipv4_between_vms_bypasses_wan() {
        let gw = lab_gateway();
        // A (192.168.124.10) sends to B (192.168.124.20): inside the CIDR —
        // the L2 switch delivers it; the WAN is bypassed.
        let frame = ipv4_frame(&MAC_B, &MAC_A, ip(192, 168, 124, 10), ip(192, 168, 124, 20));
        assert!(matches!(gw.handle_frame(PortId(1), &frame), GatewayAction::L2));
    }

    #[test]
    fn local_ipv4_to_gateway_ip_bypasses_wan() {
        let gw = lab_gateway();
        // A sends to the gateway IP itself (192.168.124.1): inside the
        // CIDR, so L2 only — serving the gateway (DNS/DHCP) is the
        // services' job (spec REQ-005/006), not the egress classifier's.
        let frame = ipv4_frame(&GW_MAC_LAB, &MAC_A, ip(192, 168, 124, 10), ip(192, 168, 124, 1));
        assert!(matches!(gw.handle_frame(PortId(1), &frame), GatewayAction::L2));
    }

    #[test]
    fn non_ip_non_arp_ethertype_is_l2_only() {
        let gw = lab_gateway();
        // 0x88b5 (local experimental): neither ARP nor IPv4 — the switch is
        // the only handler; the gateway never touches the WAN.
        let frame = eth_frame(&BCAST, &MAC_A, 0x88b5, &[0xaa, 0xbb]);
        assert!(matches!(gw.handle_frame(PortId(1), &frame), GatewayAction::L2));
    }

    // Edge cases (task list).

    #[test]
    fn arp_reply_is_not_answered() {
        let gw = lab_gateway();
        // A transmits an ARP reply (op 2) whose tpa is the gateway IP: only
        // requests (op 1) are answered, so the gateway stays silent.
        let frame = arp_frame(
            &GW_MAC_LAB,
            &MAC_A,
            2,
            &MAC_A,
            ip(192, 168, 124, 10),
            &GW_MAC_LAB,
            ip(192, 168, 124, 1),
        );
        assert!(matches!(gw.handle_frame(PortId(1), &frame), GatewayAction::L2));
    }

    #[test]
    fn arp_request_for_other_network_gateway_not_answered() {
        let gw = two_network_gateway();
        // The gateway is per-network: D (staging) asks for lab's gateway
        // 192.168.124.1 — staging's gateway is 10.0.0.1, so no answer.
        let from_d = arp_frame(&BCAST, &MAC_D, 1, &MAC_D, ip(10, 0, 0, 10), &ZERO, ip(192, 168, 124, 1));
        assert!(matches!(gw.handle_frame(PortId(9), &from_d), GatewayAction::L2));
        // And the reverse: A (lab) asks for staging's gateway 10.0.0.1 —
        // lab's gateway is 192.168.124.1, so no answer.
        let from_a = arp_frame(&BCAST, &MAC_A, 1, &MAC_A, ip(192, 168, 124, 10), &ZERO, ip(10, 0, 0, 1));
        assert!(matches!(gw.handle_frame(PortId(1), &from_a), GatewayAction::L2));
    }

    #[test]
    fn non_local_ipv4_with_short_ip_header_not_routed() {
        let gw = lab_gateway();
        // 0x0800 frame whose "IP header" is 4 bytes: too short to hold a
        // destination IP — invalid, dropped for egress (L2 only).
        let frame = eth_frame(&GW_MAC_LAB, &MAC_A, IPV4, &[0x45, 0x00, 0x00, 0x04]);
        assert!(matches!(gw.handle_frame(PortId(1), &frame), GatewayAction::L2));
    }

    #[test]
    fn non_local_ipv4_with_ihl_below_minimum_not_routed() {
        let gw = lab_gateway();
        // IHL 0 (< 5) with the dst-IP slot filled with a non-local address:
        // the header is invalid, so the frame must not be routed to the WAN
        // even though the bytes at offset 16 look non-local.
        let mut header = ipv4_header(ip(192, 168, 124, 10), ip(8, 8, 8, 8));
        header[0] = 0x40; // version 4, IHL 0
        let frame = eth_frame(&GW_MAC_LAB, &MAC_A, IPV4, &header);
        assert!(matches!(gw.handle_frame(PortId(1), &frame), GatewayAction::L2));
    }

    #[test]
    fn non_local_ipv4_from_unattached_port_not_routed() {
        let mut gw = lab_gateway();
        let frame = ipv4_frame(&GW_MAC_LAB, &MAC_A, ip(192, 168, 124, 10), ip(8, 8, 8, 8));
        // Port 77 is never attached: its egress is dropped.
        assert!(matches!(gw.handle_frame(PortId(77), &frame), GatewayAction::L2));
        // Attach, then detach: while attached the egress goes to the WAN;
        // once removed, it is dropped again.
        gw.add_port(PortId(77), "lab");
        match gw.handle_frame(PortId(77), &frame) {
            GatewayAction::Wan(wan) => assert_eq!(wan, &frame),
            other => panic!("expected Wan while attached, got {other:?}"),
        }
        assert!(gw.remove_port(PortId(77)));
        assert!(matches!(gw.handle_frame(PortId(77), &frame), GatewayAction::L2));
    }

    #[test]
    fn two_ports_same_network_each_route_to_own_wan() {
        let gw = lab_gateway();
        // A and B are both on lab and both send non-local packets. Each
        // frame is routed to its sender's own WAN output — never a shared
        // WAN, never the other port's WAN.
        let from_a = ipv4_frame(&GW_MAC_LAB, &MAC_A, ip(192, 168, 124, 10), ip(8, 8, 8, 8));
        let from_b = ipv4_frame(&GW_MAC_LAB, &MAC_B, ip(192, 168, 124, 11), ip(9, 9, 9, 9));
        assert_ne!(from_a, from_b);
        match gw.handle_frame(PortId(1), &from_a) {
            GatewayAction::Wan(wan) => assert_eq!(wan, &from_a, "A's WAN must get A's frame"),
            other => panic!("expected Wan for A, got {other:?}"),
        }
        match gw.handle_frame(PortId(2), &from_b) {
            GatewayAction::Wan(wan) => assert_eq!(wan, &from_b, "B's WAN must get B's frame"),
            other => panic!("expected Wan for B, got {other:?}"),
        }
    }

    #[test]
    fn broadcast_arp_for_gateway_answered_unicast_reply() {
        let gw = lab_gateway();
        // The canonical "who-has" broadcast (dst ff:ff:ff:ff:ff:ff) for the
        // gateway: answered, and the reply is unicast to the requester —
        // not re-broadcast.
        let frame = arp_frame(
            &BCAST,
            &MAC_A,
            1,
            &MAC_A,
            ip(192, 168, 124, 10),
            &ZERO,
            ip(192, 168, 124, 1),
        );
        let expected = arp_frame(
            &MAC_A,
            &GW_MAC_LAB,
            2,
            &GW_MAC_LAB,
            ip(192, 168, 124, 1),
            &MAC_A,
            ip(192, 168, 124, 10),
        );
        match gw.handle_frame(PortId(1), &frame) {
            GatewayAction::ArpReply(reply) => assert_eq!(reply, expected),
            other => panic!("expected ArpReply, got {other:?}"),
        }
    }

    // Boundary pins (grill-me): interactions the requirement list leaves
    // open.

    #[test]
    fn port_on_unknown_network_is_l2() {
        let mut gw = Gateway::new();
        gw.add_port(PortId(5), "ghost");
        // "ghost" is not configured: the gateway has no CIDR/gateway to act
        // on, so the frame is L2 (the switch's behavior applies).
        let frame = arp_frame(
            &BCAST,
            &MAC_A,
            1,
            &MAC_A,
            ip(192, 168, 124, 10),
            &ZERO,
            ip(192, 168, 124, 1),
        );
        assert!(matches!(gw.handle_frame(PortId(5), &frame), GatewayAction::L2));
    }
}
