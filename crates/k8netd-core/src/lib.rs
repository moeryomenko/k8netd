//! Domain model and L2 switch engine for `k8netd`.
//!
//! Owns the network/port/IPAM types, the MAC-learning switch, and the
//! persisted state store used by the vhost-user dataplane and the JSON-RPC
//! control plane (spec REQ-002..REQ-007, REQ-010).

pub mod ipam;
pub mod model;
