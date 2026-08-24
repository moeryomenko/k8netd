# k8netd — Install Contract

This document is the install contract for the k8netd daemon. It defines
everything needed to run k8netd as a podman **user quadlet** on a single lab
host: the image reference and build, the unit template, the environment
contract, the required mount, and the deliberate absence of capabilities.

The consumer is the lab operator (or the k8labs-side `mgmt` module). It is
self-contained. Every value cites its repository source so the contract can be
re-verified. Sources:

- `crates/k8netd/src/config.rs` — `K8NETD_*` resolution and defaults.
- `deploy/k8netd.container` — the committed unit template.
- `Containerfile` — image layout.
- `.specs/k8netd-contract/spec.md` — REQ-001/REQ-008/REQ-010 behavior.

---

## 1. Image reference and build

| Item | Value | Source |
|---|---|---|
| Image tag | `localhost/k8netd:dev` | `Makefile` (`IMAGE ?=`) |
| Build target | `make image` | `Makefile` |
| Build command | `podman build -t localhost/k8netd:dev -f Containerfile .` | `Makefile` |
| Entry point | `/k8netd` | `Containerfile` (ENTRYPOINT) |

The image is local-only; it is never published to a registry. Build
prerequisites: podman and network access to the Rust/Debian/distroless base
images.

### 1.1 Runtime image contents

| Component | Origin | Source |
|---|---|---|
| `k8netd` binary | Rust builder stage, channel pinned by `rust-toolchain.toml` | `Containerfile` stage 1 |
| `passt` binary | Debian builder stage matching the distroless suite | `Containerfile` stage 2 |
| `/etc/services`, `/etc/ethertypes` | carried from the passt stage | `Containerfile` stage 3 |

Suite pairing rule (`Containerfile` header): the Debian builder suite must
match the distroless flavor (`trixie` -> `cc-debian13`). Never mix suites —
a mismatch surfaces as `GLIBC_2.xx not found` at passt spawn time.

---

## 2. Startup contract

One process: the daemon binds the JSON-RPC control socket, creates the socket
directory if missing, and serves until shutdown. Port sockets are re-created
from persisted state on restart (REQ-010), so a restart re-binds every
`<port>.sock` at the same path within the cloud-hypervisor 60s reconnect
window.

Fixed values an operator should know (not configurable here):

- Control socket: `<socket-dir>/control.sock` (REQ-001).
- Per-port sockets: `<socket-dir>/<port>.sock` (REQ-003).
- State file: `<socket-dir>/state.json`, written atomically per mutation
  (REQ-010).
- Upstream DNS: forwarded over plain UDP; no TLS material needed.

---

## 3. Environment variables (`K8NETD_*`)

All values are pinned explicitly in the unit template (grill decision D7);
the defaults below come from `config.rs`.

| Variable | Pinned value | Default source |
|---|---|---|
| `K8NETD_SOCKET_DIR` | `/run/user/1000/k8snet` | `config.rs` (`DEFAULT_SOCKET_DIR`) |
| `K8NETD_PASST_BINARY` | `passt` | `config.rs` (`DEFAULT_PASST_BINARY`) |
| `K8NETD_UPSTREAM_DNS` | `1.1.1.1,8.8.8.8` | `config.rs` (`DEFAULT_UPSTREAM_DNS`) |
| `K8NETD_MTU` | `1500` | `config.rs` (`DEFAULT_MTU`) |
| `K8NETD_PUBLISH_RANGE` | `20000-21000` | `config.rs` (`DEFAULT_PUBLISH_RANGE`) |

Invalid values abort startup (`ConfigError`); flags override env overrides
defaults (`config::resolve`).

Inbound port forwards are allocated exclusively through the idempotent
`PublishPort` RPC (REQ-010) from the `K8NETD_PUBLISH_RANGE` range and are
persisted in `state.json`. The retired static-forward variables
(`K8NETD_PORT_FORWARDS`, `K8NETD_PASST_FORWARDS`) are ignored with a
deprecation warning at startup (REQ-011).

---

## 4. Quadlet unit

Install path (UID 1000 lab convention — the Go provider hardcodes this base,
`internal/chclient/vhostuser.go:30`):

```sh
install -D -m 644 deploy/k8netd.container \
    ~/.config/containers/systemd/k8netd.container
sudo loginctl enable-linger $USER   # keep the unit alive without a session
systemctl --user daemon-reload
systemctl --user start k8netd
```

The full template lives at [`deploy/k8netd.container`](../deploy/k8netd.container).
Key lines and their rationale:

```ini
[Container]
Image=localhost/k8netd:dev
Network=host
Mount=type=bind,source=/run/user/1000/k8snet,target=/run/user/1000/k8snet
Environment=K8NETD_SOCKET_DIR=/run/user/1000/k8snet
# ... remaining pins per section 3 ...

[Service]
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=tmpfs
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

---

## 5. Mounts

| Contract item | Host path | Container path | Consumed by |
|---|---|---|---|
| Socket + state dir | `/run/user/1000/k8snet` | identical (writable) | control.sock, `<port>.sock`, `state.json` |

That single bind is the whole mount surface:

- Path identity is mandatory — cloud-hypervisor runs outside the container and
  dials these exact paths (`VhostUserSocketPath`, provider repo).
- REQ-010 keeps state in the socket directory, so persistence needs no second
  mount.
- No kubeconfig, no webhook certs, no `/dev/kvm`: cloud-hypervisor does not
  run inside this container.

---

## 6. Capabilities — deliberately none

Unlike the provider quadlet (`Network=host` + `--privileged` +
`NET_ADMIN`, see the provider's `docs/install-contract.md` §6), the k8netd
unit adds **no capabilities and no privileged mode**. This is the headline of
the rootless design (spec §1: "performs no privileged host operation"):

- The L2 switch, DHCP/DNS servers, and IPAM are userspace packet handlers; the
  gateway IP is not a real interface, so no privileged port binding occurs.
- passt is designed unprivileged; with `Network=host` its inbound forwards
  bind directly on the host so a published control-plane port (allocated via
  `PublishPort`, e.g. `127.0.0.1:<host-port>`) reaches the control-plane VM
  (VC-09) and egress reaches the pinned upstream resolvers unchanged.
- Rootless podman maps host UID 1000 to container root, so files created in
  the mounted socket dir carry correct host ownership without a `USER`
  directive.

Hardening is layered on top anyway (`NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome=tmpfs`, `RestrictAddressFamilies`);
if passt ever fails to bind its forwards on a lab host, relax
`RestrictAddressFamilies` first.

---

## 7. Verification

Manual steps after install:

```sh
systemctl --user status k8netd                 # active (running)
ls /run/user/1000/k8snet/control.sock          # socket exists
python3 - <<'PY'                               # RPC ping
import json, socket
req = json.dumps({"jsonrpc":"2.0","version":"1.0",
                  "method":"GetNetwork","params":{"name":"x"},"id":1})
s = socket.socket(socket.AF_UNIX); s.connect("/run/user/1000/k8snet/control.sock")
s.sendall((req+"\n").encode()); print(s.recv(4096).decode())
PY                                             # expect not_found error JSON
```

Automated depth lives in `tests/e2e/run.sh`: when the quadlet-managed unit is
active it uses it as the system-under-test instead of hand-launching a binary;
off a lab host the script exits SKIP(77).
