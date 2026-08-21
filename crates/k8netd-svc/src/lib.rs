//! Network services for the `k8netd` switch.
//!
//! DHCP server (`dhcproto`), DNS forwarder (`hickory-proto`), and the
//! per-port passt WAN subprocess manager (spec REQ-005, REQ-006, REQ-008).

pub mod dhcp;
pub mod dns;
