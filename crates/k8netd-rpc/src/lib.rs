//! Control-plane JSON-RPC 2.0 protocol and handlers for `k8netd`.
//!
//! The Unix control socket at `<socket_dir>/control.sock`, the JSON-RPC 2.0
//! envelope with the mandatory `version` field, and the typed error codes
//! from spec REQ-001.

pub mod protocol;
pub mod server;
