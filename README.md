# k8netd

Rootless userspace vhost-user L2 switch for cloud-hypervisor VMs on a single
Linux lab host. k8netd replaces the Linux bridge + TAP + dnsmasq + nftables
stack with a vhost-user L2 switch and integrated services: IPAM, DHCP, DNS,
and a per-VM passt-based WAN. VMs attach through vhost-user sockets; the
daemon presents a real L2 segment to them, which Cilium L2 announcements
require. The daemon runs as an unprivileged user (user quadlet) and performs
no privileged host operation.

The frozen contract is [docs/k8netd-contract.spec.md](docs/k8netd-contract.spec.md)
(spec ID K8NETD-CTR-001, rev 2).

## Role

- **Dataplane**: vhost-user backend ports (single queue pair) into an L2
  switch with MAC learning, unknown/broadcast flooding, known-unicast
  forwarding, per-network gateway (ARP + DHCP + DNS), and a per-port passt
  WAN subprocess.
- **Control plane**: JSON-RPC 2.0 API over a Unix socket. The only client is
  the cluster-api-hypervisor Go provider.

## Control socket contract

- Path: `/run/user/1000/k8snet/control.sock` (configurable via
  `K8NETD_SOCKET_DIR`; spec REQ-001).
- Protocol: JSON-RPC 2.0 envelope; every request carries a `version` field
  and a mismatch returns a typed error.
- Errors carry a machine-readable code: `not_found`, `already_exists`,
  `invalid_params`, `conflict`, `internal`. `Create*` methods are idempotent.

## Workspace layout

| Crate | Role |
| ----- | ---- |
| `crates/k8netd` | Daemon binary (wires the crates together) |
| `crates/k8netd-core` | Domain model, IPAM, L2 switch engine, state persistence |
| `crates/k8netd-vhost` | vhost-user backend ports (rust-vmm) |
| `crates/k8netd-svc` | DHCP, DNS forwarder, per-port passt WAN manager |
| `crates/k8netd-rpc` | JSON-RPC 2.0 protocol, control socket server, handlers |
| `tests/` | Workspace-level integration tests (reserved) |

## Make targets

| Target | Purpose |
| ------ | ------- |
| `make check` | `cargo fmt --check` + `cargo clippy -- -D warnings` + `cargo test` (CI gate) |
| `make fmt-check` | Verify formatting |
| `make clippy` | Lint with clippy, deny warnings |
| `make test` | Run the test suite |

## Toolchain and dependencies

- Toolchain pinned in `rust-toolchain.toml` (stable 1.97.1, rustfmt + clippy).
- All dependencies pinned in `Cargo.lock` (committed).
- Formatting and clippy honor the 120-column limit (`rustfmt.toml`,
  `clippy.toml`), matching the cluster-api-hypervisor provider repo style.