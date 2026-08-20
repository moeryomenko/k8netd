//! Ethernet frame parsing (spec REQ-007, plan TASK-008, TEST-FIRST).
//!
//! TASK-008 (test-first): the `tests` module below defines the contract for
//! the frame parser. The parser does not exist yet, so the tests fail to
//! compile (red phase). TASK-009 implements the parser in this file to make
//! the tests pass; the tests module stays at the bottom of the file per Rust
//! convention.

use std::fmt;

use crate::model::MacAddr;

/// Error type for ethernet frame parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// The frame is shorter than the 14-byte ethernet header (18 bytes when
    /// the 802.1Q tag is present).
    TooShort { len: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::TooShort { len } => write!(f, "ethernet frame too short: {len} bytes"),
        }
    }
}

impl std::error::Error for FrameError {}

/// A parsed ethernet frame: header fields plus a payload slice.
///
/// The payload borrows the input buffer, so parsing allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedFrame<'a> {
    /// Destination MAC address (6 bytes at offset 0).
    pub dst: MacAddr,
    /// Source MAC address (6 bytes at offset 6).
    pub src: MacAddr,
    /// Ethertype, big-endian at offset 12. For 802.1Q-tagged frames this is
    /// the inner ethertype after the 4-byte tag.
    pub ethertype: u16,
    /// Payload bytes after the header: offset 14, or offset 18 when the
    /// 802.1Q tag is present.
    pub payload: &'a [u8],
}

impl<'a> ParsedFrame<'a> {
    /// Parses an ethernet frame from raw bytes.
    ///
    /// Recognizes the 802.1Q TPID `0x8100` at the ethertype offset, skips the
    /// 4-byte tag, and exposes the inner ethertype with the payload sliced
    /// after the tag. Frames shorter than the 14-byte header — or shorter
    /// than 18 bytes when tagged — are `FrameError::TooShort`. Unknown
    /// ethertypes and the zero MAC parse successfully; rejecting them is the
    /// forwarding engine's concern.
    pub fn parse(frame: &'a [u8]) -> Result<ParsedFrame<'a>, FrameError> {
        if frame.len() < 14 {
            return Err(FrameError::TooShort { len: frame.len() });
        }
        let dst = mac_at(frame, 0);
        let src = mac_at(frame, 6);
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        let (ethertype, payload_offset) = if ethertype == 0x8100 {
            if frame.len() < 18 {
                return Err(FrameError::TooShort { len: frame.len() });
            }
            (u16::from_be_bytes([frame[16], frame[17]]), 18)
        } else {
            (ethertype, 14)
        };
        Ok(ParsedFrame {
            dst,
            src,
            ethertype,
            payload: &frame[payload_offset..],
        })
    }
}

/// Reads the 6-byte MAC address at `offset` without allocating.
fn mac_at(frame: &[u8], offset: usize) -> MacAddr {
    let mut bytes = [0u8; 6];
    bytes.copy_from_slice(&frame[offset..offset + 6]);
    MacAddr::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    // Expected API — implemented by TASK-009 to satisfy these tests:
    //
    // pub enum FrameError {
    //     TooShort { len: usize }, // fewer than the 14-byte header
    // }
    //
    // pub struct ParsedFrame<'a> {
    //     pub dst: MacAddr,      // 6 bytes at offset 0
    //     pub src: MacAddr,      // 6 bytes at offset 6
    //     pub ethertype: u16,    // big-endian at offset 12
    //     pub payload: &'a [u8], // bytes after the header
    // }
    //
    // impl<'a> ParsedFrame<'a> {
    //     pub fn parse(frame: &'a [u8]) -> Result<ParsedFrame<'a>, FrameError>;
    // }
    //
    // 802.1Q pin (decided here): the parser recognizes TPID 0x8100 at the
    // ethertype offset, skips the 4-byte tag (TPID + TCI), and exposes the
    // inner ethertype with the payload sliced after the tag (offset 18). The
    // switch implements no VLAN filtering (spec non-objective "No VLANs"), so
    // the tag is transparent: ethertype classification sees the inner value
    // and the payload excludes the tag.
    //
    // Frames shorter than 14 bytes are `FrameError::TooShort`. Unknown
    // ethertypes and the zero MAC parse successfully; rejecting them is the
    // forwarding engine's concern (TASK-010/011).

    use super::*;
    use crate::model::MacAddr;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
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

    // REQ-1: ethernet frame parsing from known byte fixtures.

    #[test]
    fn parse_arp_frame_fixture() {
        // ARP request: 02:00:00:00:00:01 @ 192.168.124.10 asking for 192.168.124.1.
        let frame = [
            // dst: ff:ff:ff:ff:ff:ff (broadcast)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // src: 02:00:00:00:00:01
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // ethertype: 0x0806 (ARP)
            0x08, 0x06, // ARP payload (28 bytes)
            0x00, 0x01, // htype: Ethernet
            0x08, 0x00, // ptype: IPv4
            0x06, // hlen
            0x04, // plen
            0x00, 0x01, // op: request
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // sha
            0xc0, 0xa8, 0x7c, 0x0a, // spa: 192.168.124.10
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tha
            0xc0, 0xa8, 0x7c, 0x01, // tpa: 192.168.124.1
        ];
        let parsed = ParsedFrame::parse(&frame).expect("valid ARP frame");
        assert_eq!(parsed.dst, mac("ff:ff:ff:ff:ff:ff"));
        assert_eq!(parsed.src, mac("02:00:00:00:00:01"));
        assert_eq!(parsed.ethertype, 0x0806);
        assert_eq!(parsed.payload.len(), 28);
        assert_eq!(parsed.payload[0..2], [0x00, 0x01]);
        assert_eq!(parsed.payload[24..28], [0xc0, 0xa8, 0x7c, 0x01]);
        // Payload is exactly the trailing bytes — never more, never less.
        assert_eq!(parsed.payload, &frame[14..]);
    }

    #[test]
    fn parse_ipv4_frame_fixture() {
        // Minimal IPv4 packet (20-byte IP header): 192.168.124.10 -> 192.168.124.1.
        let payload = [
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0xc0, 0xa8, 0x7c, 0x0a, 0xc0, 0xa8,
            0x7c, 0x01,
        ];
        let frame = eth_frame(
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            0x0800,
            &payload,
        );
        let parsed = ParsedFrame::parse(&frame).expect("valid IPv4 frame");
        assert_eq!(parsed.dst, mac("02:00:00:00:00:02"));
        assert_eq!(parsed.src, mac("02:00:00:00:00:01"));
        assert_eq!(parsed.ethertype, 0x0800);
        assert_eq!(parsed.payload, payload.as_slice());
        assert_eq!(parsed.payload, &frame[14..]);
    }

    #[test]
    fn parse_broadcast_dst_mac() {
        // ff:ff:ff:ff:ff:ff is a normal (broadcast) destination, not an error.
        let frame = eth_frame(
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            0x0800,
            &[0xde, 0xad, 0xbe, 0xef],
        );
        let parsed = ParsedFrame::parse(&frame).expect("broadcast frame parses");
        assert_eq!(parsed.dst, mac("ff:ff:ff:ff:ff:ff"));
    }

    #[test]
    fn parse_zero_src_mac() {
        // 00:00:00:00:00:00 parses at the frame layer; the MAC table policy
        // for learning zero MACs is pinned separately in mac_table.rs.
        let frame = eth_frame(
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            0x0806,
            &[0x00; 8],
        );
        let parsed = ParsedFrame::parse(&frame).expect("zero source MAC parses");
        assert_eq!(parsed.src, mac("00:00:00:00:00:00"));
        assert_eq!(parsed.ethertype, 0x0806);
    }

    #[test]
    fn parse_unknown_ethertype_is_not_error() {
        // 0x88b5 (local experimental) must parse; ethertype classification
        // belongs to the forwarding engine, not the parser.
        let frame = eth_frame(
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            0x88b5,
            &[0xaa, 0xbb],
        );
        let parsed = ParsedFrame::parse(&frame).expect("unknown ethertype parses");
        assert_eq!(parsed.ethertype, 0x88b5);
        assert_eq!(parsed.payload, [0xaa, 0xbb]);
    }

    #[test]
    fn parse_exact_14_byte_header_no_payload() {
        // Minimum valid frame: header only, empty payload.
        let frame = eth_frame(
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            0x0800,
            &[],
        );
        let parsed = ParsedFrame::parse(&frame).expect("header-only frame parses");
        assert_eq!(parsed.ethertype, 0x0800);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn parse_frame_shorter_than_header_is_error() {
        // 13 bytes is one byte short of the 14-byte header.
        let short = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08,
        ];
        let err = ParsedFrame::parse(&short).expect_err("13-byte frame must be rejected");
        assert!(matches!(err, FrameError::TooShort { .. }));
    }

    #[test]
    fn parse_empty_frame_is_error() {
        let err = ParsedFrame::parse(&[]).expect_err("empty frame must be rejected");
        assert!(matches!(err, FrameError::TooShort { .. }));
    }

    #[test]
    fn parse_vlan_tagged_frame_skips_tag() {
        // 802.1Q pin: TPID 0x8100 at offset 12, TCI at 14-15, inner ethertype
        // 0x0800 at 16-17, payload from offset 18. The parser skips the tag
        // and exposes the inner ethertype.
        let mut frame = Vec::with_capacity(18 + 4);
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]); // dst
        frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // src
        frame.extend_from_slice(&[0x81, 0x00]); // TPID 0x8100
        frame.extend_from_slice(&[0x00, 0x64]); // TCI (VID 100, prio 0)
        frame.extend_from_slice(&[0x08, 0x00]); // inner ethertype: IPv4
        frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
        let parsed = ParsedFrame::parse(&frame).expect("tagged frame parses");
        assert_eq!(parsed.ethertype, 0x0800);
        assert_eq!(parsed.payload, [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parsed.payload, &frame[18..]);
    }
}
