# Spec: k8netd Contract (k8netd repo)

- Status: APPROVED (2026-08-20)
- Author: spec-architect (grill session, 2026-08-20)
- Spec ID: K8NETD-CTR-001
- Revision: 3
- Revision 2 (2026-08-20): per-VM passt replaces shared WAN after the passt
  single-guest spike (REQ-008); switch drops inbound L3 routing (REQ-007);
  state persistence and re-listen added (REQ-010) after the cloud-hypervisor
  reconnect spike; risks and research findings updated.
- Revision 3 (2026-08-23): static passt forwards retired; inbound forwards
  come exclusively from the idempotent PublishPort RPC backed by a persisted
  allocator (REQ-011, capishim-hypervisor-integration D9).
- Note: this spec belongs in the k8netd repository (separate git repo). It is
  drafted here as an artifact for transfer; the provider-side integration spec
  (`.specs/k8netd-integration/spec.md`) references it as the external contract.

## 1. Overview

k8netd is a rootless userspace network daemon for cloud-hypervisor VMs on a
single Linux lab host. It replaces the Linux bridge + TAP + dnsmasq + nftables
stack with a vhost-user L2 switch and integrated services: IPAM, DHCP, DNS,
and a passt-based WAN. VMs attach through vhost-user sockets; the daemon
presents a real L2 segment to them, which Cilium L2 announcements require.
The daemon runs as an unprivileged user (user quadlet) and performs no
privileged host operation.

The control plane is a JSON-RPC 2.0 API over a Unix socket; the dataplane is
the vhost-user L2 switch. The only client is the cluster-api-hypervisor Go
provider.

## 2. Context

- Rust implementation. Dataplane built on rust-vmm crates (`vhost-user-backend`,
  `vm-memory`, `vhost`); async runtime tokio; DHCP wire handling via
  `dhcproto`; DNS wire handling via `hickory-proto`.
- Daemon config comes from CLI flags / `K8NETD_*` env vars at startup: socket
  directory (default `/run/user/1000/k8snet/`), passt binary path, upstream
  DNS resolvers (default 1.1.1.1, 8.8.8.8), MTU (default 1500), and the
  PublishPort allocation range (`K8NETD_PUBLISH_RANGE`, default 20000-21000).
  Dynamic state (networks, ports, IPs, published forwards) comes exclusively
  through the JSON-RPC API.
- WAN: one shared passt subprocess per daemon instance, connected via an
  AF_UNIX socketpair (`passt -F/--fd`); frames on the socket carry a 4-byte
  vnet header; `-F` implies `--one-off`, so the daemon owns the passt
  lifecycle and restarts it if it exits.
- The daemon serves DHCP and DNS as packet handlers inside the switch (the
  gateway IP is a userspace address, not a real interface), so no privileged
  port binding is needed.

## 3. Technical Requirements

### REQ-001: Control socket
Listen on `/run/user/1000/k8snet/control.sock` (configurable). JSON-RPC 2.0
envelope. Every request carries a `version` field; a mismatch returns a typed
error. Errors carry a machine-readable code: `not_found`, `already_exists`,
`invalid_params`, `conflict`, `internal`. `Create*` methods are idempotent:
no-op success when the object exists with identical params, `conflict` when
params differ.

### REQ-002: Network model
A Network is an L2 segment with a name, IPv4 CIDR, gateway address, and
allocation pool bounds. Methods: CreateNetwork, DeleteNetwork, GetNetwork.
Networks are isolated L2 segments; no inter-network routing.

### REQ-003: Port model
A Port is a vhost-user backend endpoint: a listening Unix socket under the
socket directory named `<port>.sock`. Methods: CreatePort (creates the socket
only), DeletePort (destroys the socket), GetPort, AttachPort (joins the port
to a network's L2 segment), DetachPort (removes it; socket stays alive).
Ports are single queue pair.

### REQ-004: IPAM
AllocateIP(network, mac) returns an IP from the network's pool and binds it
to the MAC as a DHCP reservation. ReleaseIP(network, mac) frees it. The
control-plane IP is reserved before the VM boots so kubeadm/PKI config can
reference it.

### REQ-005: DHCP
RFC 2131 server handled inside the switch on the network's gateway. Honors
AllocateIP reservations (a reserved MAC always receives its reserved IP).
Options delivered: gateway, DNS (the gateway), lease time. Lease state is
queryable through GetNetwork/GetPort.

### REQ-006: DNS
Forwarder served on the gateway IP:53, forwarding to the pinned upstream
resolvers. No local zones; CoreDNS in the cluster is untouched.

### REQ-007: L2 switch
MAC learning table, unknown-unicast and broadcast/multicast flooding, known-
unicast forwarding between ports on the same network. Gateway function per
network: answer ARP for the gateway address; forward each port's non-local IP
packets to that port's own passt WAN port. No inbound L3 routing: per-VM passt
handles inbound to its single guest deterministically. No special handling for
Cilium L2 announcements: ARP floods reach all ports and the Cilium agent
answers.

### REQ-008: WAN (per-VM passt)
One passt subprocess per attached port, connected via an AF_UNIX socketpair
(`passt -F/--fd`), speaking the passt socket protocol (vnet header + ethernet
frame). Each instance is pinned to its VM: `-a <vm-ip>` address pinning and
explicit port-forward rules rendered from that port's published entries only
(REQ-011: one `-t <host>:<vm-ip>/<vm>` per PublishPort allocation; never
relying on auto-detected guest addresses). The daemon owns every passt
lifecycle: spawn on attach, restart on exit, terminate on detach. While a
VM's passt is down, that VM has no egress and its inbound ports are
unreachable; other VMs are unaffected.

### REQ-009: vhost-user backend
rust-vmm `vhost-user-backend` per port; single queue pair; shared memory via
memfd; correct feature negotiation with the cloud-hypervisor frontend.

### REQ-010: State persistence and re-listen
Persist all dynamic state (networks, ports, attachments, IPAM allocations,
DHCP leases) to disk in the socket directory and restore it on startup, so a
restart re-binds every port socket at the same path. Implement an
accept/re-listen loop per port (the `vhost-user-backend` crate serves one
connection then returns) and unlink stale socket files before binding.
Restart must complete within 60 seconds of a disconnect so cloud-hypervisor
frontends reconnect before their retry window expires.

### REQ-011: PublishPort RPC (inbound forwards)
Idempotent JSON-RPC method `PublishPort {port, vm_port} -> {host_port}` is
the only source of inbound passt forwards. The daemon owns a host-port
allocator persisted in `state.json` (allocations survive restart); the range
defaults to 20000-21000 and is configurable via `K8NETD_PUBLISH_RANGE`
(warning at startup when it overlaps the ephemeral port range). Re-publishing
identical params returns the same host_port; distinct `vm_port`s get distinct
allocations; unknown/unattached ports are rejected; exhaustion returns a
typed error with no partial state; allocations are freed on DetachPort or
DeletePort of the owning port. The retired static-forward variables
(`K8NETD_PORT_FORWARDS`, `K8NETD_PASST_FORWARDS`) are ignored with a
deprecation warning.

## 4. Verification Contract

### VC-01: switch forwarding
- Condition: unit tests prove MAC learning, known-unicast forwarding, and
  flooding of unknown/broadcast frames between ports on the same network, and
  isolation between networks.
- Type: UNIT

### VC-02: gateway function
- Condition: unit tests prove ARP answers for the gateway address and egress
  forwarding of each port's non-local IP to that port's own passt WAN port;
  no inbound routing path exists in the switch.
- Type: UNIT

### VC-03: IPAM
- Condition: unit tests prove allocation from the pool, IP↔MAC binding,
  release, and exhaustion behavior.
- Type: UNIT

### VC-04: DHCP
- Condition: unit tests prove DISCOVER/OFFER/REQUEST/ACK against `dhcproto`
  fixtures, reservation honoring, and option delivery (gateway, DNS, lease).
- Type: UNIT

### VC-05: DNS
- Condition: unit tests prove forwarding to upstream resolvers and response
  relay.
- Type: UNIT

### VC-06: RPC contract
- Condition: unit tests prove JSON-RPC 2.0 envelope, typed error codes,
  idempotent creates, and version mismatch rejection.
- Type: UNIT

### VC-07: vhost-user protocol
- Condition: integration tests drive the backend with a fake vhost-user
  frontend (feature negotiation, memfd mapping, virtqueue kick/call) and
  observe frame exchange.
- Type: INTEGRATION

### VC-08: passt WAN
- Condition: integration test spawns per-VM passt instances via socketpair
  with `-a` pinning and explicit `-t` rules, and proves frame exchange and
  port-forward reachability for each VM on a host with passt installed.
- Type: INTEGRATION

### VC-10: state persistence
- Condition: unit/integration test restarts the daemon and proves networks,
  ports, attachments, IPAM allocations, and leases are restored and port
  sockets re-bound at the same paths.
- Type: INTEGRATION

### VC-09: full e2e
- Condition: on a lab host, cloud-hypervisor VMs attached via vhost-user
  reach each other, the gateway, and the internet through passt; inbound
  `127.0.0.1:<published host port>` reaches the control-plane VM via its
  PublishPort allocation.
- Type: E2E (lab host only)

## 5. Non-Objectives

- No multi-queue vhost-user; single queue pair per port.
- No IPv6.
- No VLANs or inter-network routing; networks are isolated L2 segments.
- No CoreDNS replacement; DNS is upstream forwarding only.
- No host-side L2 access: the host is not on any L2 segment; LoadBalancer
  VIPs announced via Cilium L2 are reachable only from within the segment.
- No TAP devices, bridges, nftables, or any privileged host operation.
- No DHCP client behavior; the daemon is server-only.

## 6. Risks and Unknowns

- **Host-port collision across clusters**: per-VM passt forwards bind host
  ports. Resolved by the PublishPort allocator (REQ-011): each allocation
  comes from a distinct slot in `K8NETD_PUBLISH_RANGE`, so concurrent
  clusters never collide on 6443/22.
- **60-second restart window**: cloud-hypervisor reconnects vhost-user
  backends only within 60s of disconnect; beyond that NICs are dead until VM
  restart. REQ-010 (persistence + fast re-listen) bounds this risk.
- **passt single-guest contract**: per-VM passt instances are the documented
  model (qrap, libvirt, RHEL 10); the daemon must never share one passt
  across ports.
- Contract drift with the Go provider is guarded by the `version` field; the
  provider must fail loudly on mismatch.

## 7. Research Findings

- **passt is strictly single-guest (spike, HIGH confidence)**: with multiple
  VMs behind one socket, inbound `-t` forwarding is ambiguous (single
  last-writer-wins `addr_seen`/`guest_mac` slot; DHCP offers the same address
  to every requester; maintainers confirm multi-guest-per-PIF unsupported).
  The documented model is one passt per VM with explicit `-a` pinning and
  `-t 6443:<vm-ip>/6443` rules (qrap, libvirt, RHEL 10). This drove the
  per-VM passt decision (REQ-008).
- **cloud-hypervisor auto-reconnects vhost-user backends (spike, 95%)**:
  client mode (default) retries the socket path every 100ms for 60s; the
  guest is unaware. Beyond 60s the NIC is marked NEEDS_RESET and stays dead
  until VM restart. The rust-vmm `vhost-user-backend` crate serves one
  connection then returns, so the daemon needs its own accept/re-listen loop
  and must unlink stale sockets on restart (REQ-010).
- passt `-F/--fd` takes a pre-opened connected Unix socket (qrap pattern);
  frames carry a 4-byte vnet header; `-F` implies `--one-off`. pasta `-F`
  takes a pre-opened TAP device fd, which does not fit the switch-owned-WAN
  model. passt also offers `--vhost-user` mode (daemon acts as a vhost-user
  backend itself) and `-t`/`-u` port forwards. (passt(1) man pages,
  passt-dev list.)
- rust-vmm `vhost-user-backend` is the stack cloud-hypervisor uses for its
  vhost-user devices, guaranteeing protocol compatibility.
- `dhcproto` and `hickory-proto` are the standard Rust crates for DHCP and
  DNS wire handling.