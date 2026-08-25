//! vhost-user backend ports for the `k8netd` L2 switch.
//!
//! Implements the vhost-user backend endpoints (`vhost-user-backend`) that
//! cloud-hypervisor frontends attach to, each serving one virtio-net queue
//! pair as two vrings (RX 0 + TX 1), with the accept/re-listen loop and
//! stale-socket unlink from spec REQ-009/REQ-010.

/// Test-only vhost-user CLIENT (frontend) used by integration tests across
/// the workspace. Harmless in release builds; not part of the daemon API.
#[doc(hidden)]
pub mod fake_frontend;

pub mod port;
