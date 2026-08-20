//! L2 forwarding/flooding engine (spec REQ-007, plan TASK-010, TEST-FIRST).
//!
//! TASK-010 (test-first): the `tests` module below defines the contract for
//! the forwarding engine. The engine does not exist yet, so the tests fail
//! to compile (red phase). TASK-011 implements the engine in this file to
//! make the tests pass; the tests module stays at the bottom of the file per
//! Rust convention.

use std::collections::HashMap;

use crate::model::MacAddr;
use crate::switch::frame::ParsedFrame;
use crate::switch::mac_table::{MacTable, PortId};

/// Upper bound on learned MAC entries.
///
/// The spec pins no table size; a lab switch sees at most one MAC per VM
/// plus a handful of service MACs, so 1024 entries is generous. Beyond the
/// bound, eviction is the table's recency-based (LRU) policy.
const MAC_TABLE_CAPACITY: usize = 1024;

/// An L2 forwarding/flooding engine: MAC learning, known-unicast forwarding,
/// and unknown-unicast/broadcast/multicast flooding per network (spec REQ-007).
///
/// The engine is synchronous with no I/O. `forward` learns the source MAC of
/// every valid frame arriving at a live port, then classifies the
/// destination: a set I-bit (bit 0 of the first destination octet) marks the
/// destination as broadcast or multicast and always floods, ignoring any
/// table entry; a known unicast is delivered only to the learned port when
/// that port is live on the same network as the ingress; an unknown unicast
/// floods to every other port on the ingress's network. Frames are never
/// modified, never echoed back to the ingress port, and never cross
/// networks.
#[derive(Debug)]
pub struct Switch {
    /// Live ports keyed by handle, mapped to their network name.
    ports: HashMap<PortId, String>,
    /// The MAC learning table (recency-based LRU).
    table: MacTable,
}

impl Switch {
    /// Creates an empty switch with no ports and an empty MAC table.
    pub fn new() -> Switch {
        Switch {
            ports: HashMap::new(),
            table: MacTable::new(MAC_TABLE_CAPACITY),
        }
    }

    /// Adds `port` to the switch on the network named `network`.
    ///
    /// Re-adding an existing port replaces its network attachment.
    pub fn add_port(&mut self, port: PortId, network: &str) {
        self.ports.insert(port, network.to_string());
    }

    /// Removes `port` from the switch; returns true when the port was live.
    ///
    /// A removed port stops sending and receiving. MAC entries learned on it
    /// are kept: a stale entry resolves to a dead port and drops the frame
    /// rather than flooding (eviction is the table's LRU policy, not
    /// removal's).
    pub fn remove_port(&mut self, port: PortId) -> bool {
        self.ports.remove(&port).is_some()
    }

    /// Forwards `frame` arriving at `ingress`, returning the per-port egress.
    ///
    /// Returns one `(port, frame)` pair per output port, where the frame is
    /// the unchanged input bytes (an L2 switch never modifies frames).
    ///
    /// Behavior: the source MAC is learned before the frame is forwarded or
    /// flooded; broadcast/multicast destinations (a set I-bit) always flood,
    /// ignoring any table entry; a known unicast is delivered only to the
    /// learned port when that port is live on the same network as the ingress
    /// (a destination learned on another network is unknown within the
    /// ingress's network and floods there); an unknown unicast floods to
    /// every other port on the ingress's network. Frames at ports that were
    /// never added or were removed, and unparseable frames, are dropped
    /// without learning.
    pub fn forward<'a>(&mut self, ingress: PortId, frame: &'a [u8]) -> Vec<(PortId, &'a [u8])> {
        let network = match self.ports.get(&ingress) {
            Some(network) => network,
            None => return Vec::new(),
        };
        let parsed = match ParsedFrame::parse(frame) {
            Ok(parsed) => parsed,
            Err(_) => return Vec::new(),
        };
        // Learn-then-forward: the source MAC is learned before any lookup.
        self.table.learn(ingress, parsed.src);
        let egress = if is_local_unicast(frame) {
            self.unicast_egress(network, ingress, parsed.dst)
        } else {
            self.flood_set(network, ingress)
        };
        egress.iter().copied().map(|port| (port, frame)).collect()
    }

    /// The egress for a unicast destination arriving on `network`.
    ///
    /// A learned destination is delivered only to its port when that port is
    /// live on the same network; a destination learned on another network is
    /// unknown within `network` and floods there; a destination that resolves
    /// to the ingress port (no echo) or to a removed port (stale entry) is
    /// dropped.
    fn unicast_egress(&self, network: &str, ingress: PortId, dst: MacAddr) -> Vec<PortId> {
        match self.table.lookup(dst) {
            Some(port) if port == ingress => Vec::new(),
            Some(port) => match self.ports.get(&port) {
                None => Vec::new(),
                Some(target) if target == network => vec![port],
                Some(_) => self.flood_set(network, ingress),
            },
            None => self.flood_set(network, ingress),
        }
    }

    /// Every live port on `network` except `exclude`.
    ///
    /// Membership is by port attachment, not by learned MAC: a port that
    /// never transmitted is still a flood destination.
    fn flood_set(&self, network: &str, exclude: PortId) -> Vec<PortId> {
        self.ports
            .iter()
            .filter(|(port, attached)| **port != exclude && attached.as_str() == network)
            .map(|(port, _)| *port)
            .collect()
    }
}

impl Default for Switch {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true when the destination MAC is a local unicast: the I-bit (bit
/// 0 of the first destination octet) is clear. A set I-bit marks the
/// destination as broadcast or multicast.
fn is_local_unicast(frame: &[u8]) -> bool {
    frame[0] & 0x01 == 0
}

#[cfg(test)]
mod tests {
    // Expected API — implemented by TASK-011 to satisfy these tests:
    //
    // pub struct Switch { ... }
    //
    // impl Switch {
    //     pub fn new() -> Switch
    //     pub fn add_port(&mut self, port: PortId, network: &str)
    //     pub fn remove_port(&mut self, port: PortId) -> bool
    //     pub fn forward(&mut self, ingress: PortId, frame: &[u8]) -> Vec<(PortId, &[u8])>
    // }
    //
    // The engine drives the existing `ParsedFrame::parse` (no re-parsing of
    // the header) and the existing `MacTable` (recency-based LRU). It is
    // synchronous, has no I/O, and returns the per-port egress: one
    // `(port, frame)` pair per output port, where `frame` is the unchanged
    // input bytes (an L2 switch never modifies frames). Ports are opaque
    // `PortId` handles; a network is identified by its name
    // (`Network.name`).
    //
    // Behavior pins (decided here):
    //
    // 1. Learn-then-forward: the source MAC of every valid frame arriving at
    //    a known port is learned before the frame is forwarded or flooded.
    // 2. Classification order: the destination is classified as
    //    broadcast/multicast (the I-bit, bit 0, of the first destination
    //    octet is set) before any unicast table lookup. Broadcast and
    //    multicast always flood; a table entry for such a destination is
    //    ignored (broadcast/multicast wins over unicast).
    // 3. Flood set: every port on the ingress's network except the ingress.
    //    Membership is by port attachment, not by learned MAC — a port that
    //    never transmitted is still a flood destination.
    // 4. Known unicast: delivered only to the looked-up port, and only when
    //    that port is a live port on the same network as the ingress. A
    //    destination learned on another network is treated as unknown within
    //    the ingress's network (flood within the ingress's network; never
    //    delivered cross-network).
    // 5. No echo: a frame is never delivered back to the port it arrived on,
    //    including when the destination resolves to the ingress port.
    // 6. Frames at ports that were never added, or were removed, are dropped
    //    and never learned.
    // 7. remove_port stops a port from sending and receiving and reports
    //    false for unknown ports. MAC entries learned on it are kept (a
    //    stale entry resolves to a dead port and drops the frame rather than
    //    flooding); eviction is the table's LRU policy, not removal's.
    // 8. Unparseable frames (`FrameError`) are dropped: no output, no
    //    learning; the engine stays usable afterwards.

    use super::*;
    use crate::switch::mac_table::PortId;

    const MAC_A: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const MAC_B: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    const MAC_C: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x03];
    const MAC_X: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
    const BCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    const IGMP: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01];
    const IPV4: u16 = 0x0800;

    /// Builds an untagged ethernet frame from header parts and a payload.
    fn eth_frame(dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.extend_from_slice(dst);
        frame.extend_from_slice(src);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// The egress ports of a `forward` result, sorted (output order is not
    /// part of the contract).
    fn egress(out: &[(PortId, &[u8])]) -> Vec<PortId> {
        let mut ports: Vec<PortId> = out.iter().map(|(port, _)| *port).collect();
        ports.sort_by_key(|port| port.0);
        ports
    }

    /// Every delivered frame must be byte-identical to the input frame.
    fn assert_frames_unmodified(out: &[(PortId, &[u8])], frame: &[u8]) {
        for (_, delivered) in out {
            assert_eq!(*delivered, frame);
        }
    }

    /// A switch with three ports (A, B, C) on the "lab" network.
    fn lab_switch() -> Switch {
        let mut sw = Switch::new();
        sw.add_port(PortId(1), "lab");
        sw.add_port(PortId(2), "lab");
        sw.add_port(PortId(3), "lab");
        sw
    }

    /// A switch with A, B, C on "lab" and D on "staging".
    fn two_network_switch() -> Switch {
        let mut sw = Switch::new();
        sw.add_port(PortId(1), "lab");
        sw.add_port(PortId(2), "lab");
        sw.add_port(PortId(3), "lab");
        sw.add_port(PortId(9), "staging");
        sw
    }

    // REQ-1: known-unicast forwarding.

    #[test]
    fn known_unicast_delivered_only_to_learned_port() {
        let mut sw = lab_switch();
        // B transmits to an unlearned destination: floods to A and C, and
        // B's MAC is learned on B.
        let from_b = eth_frame(&MAC_X, &MAC_B, IPV4, &[]);
        let out = sw.forward(PortId(2), &from_b);
        assert_eq!(egress(&out), vec![PortId(1), PortId(3)]);
        // A now sends to B's learned MAC: delivered only to B, never to C.
        let from_a = eth_frame(&MAC_B, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &from_a);
        assert_eq!(egress(&out), vec![PortId(2)]);
        assert_frames_unmodified(&out, &from_a);
        // And the reverse direction: C sends to A's MAC (learned by the
        // previous frame): delivered only to A.
        let from_c = eth_frame(&MAC_A, &MAC_C, IPV4, &[0xbe, 0xef]);
        let out = sw.forward(PortId(3), &from_c);
        assert_eq!(egress(&out), vec![PortId(1)]);
    }

    #[test]
    fn tagged_frame_forwarded_like_untagged() {
        // The engine drives ParsedFrame::parse, which is transparent to
        // 802.1Q tags: the MACs at offsets 0/6 are learned and forwarded as
        // usual.
        let mut sw = lab_switch();
        let mut tagged = Vec::new();
        tagged.extend_from_slice(&MAC_X); // dst
        tagged.extend_from_slice(&MAC_B); // src
        tagged.extend_from_slice(&[0x81, 0x00]); // TPID 0x8100
        tagged.extend_from_slice(&[0x00, 0x64]); // TCI (VID 100, prio 0)
        tagged.extend_from_slice(&[0x08, 0x00]); // inner ethertype: IPv4
        tagged.extend_from_slice(&[0xde, 0xad]); // payload
        let out = sw.forward(PortId(2), &tagged);
        assert_eq!(egress(&out), vec![PortId(1), PortId(3)]);
        // B's MAC was learned from the tagged frame: A's untagged frame to
        // it reaches only B.
        let from_a = eth_frame(&MAC_B, &MAC_A, IPV4, &[0xbe, 0xef]);
        let out = sw.forward(PortId(1), &from_a);
        assert_eq!(egress(&out), vec![PortId(2)]);
    }

    // REQ-2: unknown-unicast flooding.

    #[test]
    fn unknown_unicast_floods_all_ports_except_source() {
        let mut sw = lab_switch();
        let frame = eth_frame(&MAC_X, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &frame);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
        assert_frames_unmodified(&out, &frame);
    }

    #[test]
    fn flood_reaches_port_that_never_transmitted() {
        // The flood set is defined by port membership on the network, not by
        // the MAC table: C has never transmitted (no learned MAC) and must
        // still receive the flood.
        let mut sw = lab_switch();
        // B transmits first, so the table holds B's MAC only.
        let from_b = eth_frame(&MAC_X, &MAC_B, IPV4, &[]);
        let out = sw.forward(PortId(2), &from_b);
        assert_eq!(egress(&out), vec![PortId(1), PortId(3)]);
        // A sends to an unlearned destination: C (never transmitted) is
        // still a flood destination.
        let frame = eth_frame(&MAC_X, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &frame);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
    }

    // REQ-3: broadcast and multicast flooding.

    #[test]
    fn broadcast_floods_all_ports_except_source() {
        let mut sw = lab_switch();
        let frame = eth_frame(&BCAST, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &frame);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
        assert_frames_unmodified(&out, &frame);
    }

    #[test]
    fn multicast_floods_even_when_dst_learned() {
        // The I-bit of the destination makes it multicast; a table entry for
        // the same MAC (learned from a pathological source) must not turn the
        // flood into a unicast.
        let mut sw = lab_switch();
        let pathological = eth_frame(&MAC_X, &IGMP, IPV4, &[]);
        let out = sw.forward(PortId(2), &pathological);
        assert_eq!(egress(&out), vec![PortId(1), PortId(3)]);
        let frame = eth_frame(&IGMP, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &frame);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
    }

    #[test]
    fn broadcast_floods_even_when_dst_learned() {
        // Same as the multicast case for ff:ff:ff:ff:ff:ff: broadcast wins
        // over a unicast lookup of the same address.
        let mut sw = lab_switch();
        let pathological = eth_frame(&MAC_X, &BCAST, IPV4, &[]);
        let out = sw.forward(PortId(2), &pathological);
        assert_eq!(egress(&out), vec![PortId(1), PortId(3)]);
        let frame = eth_frame(&BCAST, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &frame);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
    }

    // REQ-4: network isolation.

    #[test]
    fn cross_network_learned_dst_floods_within_ingress_network() {
        // MAC_X is learned on D (staging). A (lab) sends to MAC_X: the entry
        // points at another network, so within lab the destination is unknown
        // — the frame floods to the other lab ports and never reaches D.
        let mut sw = two_network_switch();
        // D transmits on staging, learning MAC_X on D. Staging has no other
        // ports, so the flood is empty.
        let from_d = eth_frame(&MAC_B, &MAC_X, IPV4, &[]);
        let out = sw.forward(PortId(9), &from_d);
        assert!(out.is_empty());
        // A's frame to MAC_X stays on lab.
        let frame = eth_frame(&MAC_X, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &frame);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
        assert_frames_unmodified(&out, &frame);
    }

    #[test]
    fn broadcast_never_crosses_networks() {
        let mut sw = two_network_switch();
        let frame = eth_frame(&BCAST, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &frame);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
        // From the staging side: D's broadcast has no staging peers and must
        // not leak to lab.
        let from_d = eth_frame(&BCAST, &MAC_X, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(9), &from_d);
        assert!(out.is_empty());
    }

    // Edge cases (task list).

    #[test]
    fn no_echo_to_ingress_port() {
        // A's MAC is learned on A; a frame from A to its own MAC must be
        // dropped, not echoed back to A.
        let mut sw = lab_switch();
        let from_a = eth_frame(&MAC_X, &MAC_A, IPV4, &[]);
        let out = sw.forward(PortId(1), &from_a);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
        let self_addr = eth_frame(&MAC_A, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &self_addr);
        assert!(out.is_empty());
    }

    #[test]
    fn learning_happens_before_forwarding() {
        // A new source MAC is learned and the same frame is still forwarded
        // (flooded, since the destination is unlearned).
        let mut sw = lab_switch();
        let from_a = eth_frame(&MAC_X, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &from_a);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
        // The learning is visible: B's frame to A's MAC reaches only A.
        let from_b = eth_frame(&MAC_A, &MAC_B, IPV4, &[0xbe, 0xef]);
        let out = sw.forward(PortId(2), &from_b);
        assert_eq!(egress(&out), vec![PortId(1)]);
    }

    #[test]
    fn single_port_network_has_no_flood_destination() {
        let mut sw = Switch::new();
        sw.add_port(PortId(1), "lab");
        let frame = eth_frame(&MAC_X, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &frame);
        assert!(out.is_empty());
    }

    #[test]
    fn mac_moved_between_ports_relearns() {
        // MAC_X first appears on A, then moves to B. The table holds one
        // port per MAC; re-learning moves the entry, so C's frame to MAC_X
        // reaches only the new home (B), not the stale one (A).
        let mut sw = lab_switch();
        let from_a = eth_frame(&MAC_C, &MAC_X, IPV4, &[]);
        let out = sw.forward(PortId(1), &from_a);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
        let from_b = eth_frame(&MAC_C, &MAC_X, IPV4, &[0x01]);
        let out = sw.forward(PortId(2), &from_b);
        assert_eq!(egress(&out), vec![PortId(1), PortId(3)]);
        let from_c = eth_frame(&MAC_X, &MAC_C, IPV4, &[0x02]);
        let out = sw.forward(PortId(3), &from_c);
        assert_eq!(egress(&out), vec![PortId(2)]);
    }

    // Boundary pins (grill-me): interactions the requirement list leaves
    // open.

    #[test]
    fn frame_at_unknown_port_is_dropped_and_not_learned() {
        let mut sw = lab_switch();
        let frame = eth_frame(&MAC_X, &MAC_X, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(99), &frame);
        assert!(out.is_empty());
        // No learning from an unknown ingress: A's frame to MAC_X is still
        // flooded. (If MAC_X had been learned on the unknown port, the
        // lookup would resolve to a dead port and the frame would be
        // dropped.)
        let from_a = eth_frame(&MAC_X, &MAC_A, IPV4, &[0xbe, 0xef]);
        let out = sw.forward(PortId(1), &from_a);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
    }

    #[test]
    fn malformed_frame_is_dropped_and_switch_stays_usable() {
        let mut sw = lab_switch();
        // 13 bytes: one short of the 14-byte header (FrameError::TooShort).
        let short = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08,
        ];
        let out = sw.forward(PortId(1), &short);
        assert!(out.is_empty());
        // The engine is unaffected: a valid frame still floods.
        let frame = eth_frame(&MAC_X, &MAC_A, IPV4, &[0xde, 0xad]);
        let out = sw.forward(PortId(1), &frame);
        assert_eq!(egress(&out), vec![PortId(2), PortId(3)]);
    }

    #[test]
    fn removed_port_stops_sending_and_receiving() {
        let mut sw = lab_switch();
        // B transmits, learning B's MAC.
        let from_b = eth_frame(&MAC_X, &MAC_B, IPV4, &[]);
        let out = sw.forward(PortId(2), &from_b);
        assert_eq!(egress(&out), vec![PortId(1), PortId(3)]);
        assert!(sw.remove_port(PortId(2)));
        // A frame at the removed port is dropped.
        let at_b = eth_frame(&MAC_X, &MAC_B, IPV4, &[0x01]);
        let out = sw.forward(PortId(2), &at_b);
        assert!(out.is_empty());
        // A's frame to B's stale MAC is dropped, not flooded: removal keeps
        // the table entry, and a stale entry resolves to a dead port.
        let from_a = eth_frame(&MAC_B, &MAC_A, IPV4, &[0x02]);
        let out = sw.forward(PortId(1), &from_a);
        assert!(out.is_empty());
        // A's broadcast now floods only to C (B is gone).
        let bcast = eth_frame(&BCAST, &MAC_A, IPV4, &[0x03]);
        let out = sw.forward(PortId(1), &bcast);
        assert_eq!(egress(&out), vec![PortId(3)]);
        // Removing an unknown port reports false.
        assert!(!sw.remove_port(PortId(99)));
    }
}
