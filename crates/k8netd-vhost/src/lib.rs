//! vhost-user backend ports for the `k8netd` L2 switch.
//!
//! Implements the single-queue-pair vhost-user backend endpoints
//! (`vhost-user-backend`) that cloud-hypervisor frontends attach to, with
//! the accept/re-listen loop and stale-socket unlink from spec REQ-009/REQ-010.
