#!/usr/bin/env bash
# k8netd full e2e with cloud-hypervisor (spec VC-09; plan TASK-034/035).
#
# LAB-HOST ONLY — requires KVM, cloud-hypervisor, passt, and a bootable base
# image. Never run casually (repo convention); safe to invoke anywhere because
# it exits SKIP when prerequisites are missing.
#
# Scenario under test (VC-09):
#   1. k8netd runs as an unprivileged user; control socket answers JSON-RPC.
#   2. CreateNetwork + two CreatePort + AttachPort via the control socket.
#   3. Two cloud-hypervisor VMs attach through the vhost-user port sockets.
#   4. VMs obtain DHCP leases; VM-A pings VM-B and the gateway; both reach
#      the internet through their per-VM passt.
#   5. Port forward: 127.0.0.1:6443 reaches a listener inside VM-A.
#   6. Restart gate (REQ-010): SIGKILL the daemon, restart within 60s,
#      re-create topology, reconnect a frontend — socket re-listens.
#
# Pass/fail gates are the exit codes of each step; any failure aborts non-zero.

set -euo pipefail

readonly SOCKET_DIR="${K8NETD_SOCKET_DIR:-/tmp/k8netd-e2e.$$}"
readonly CONTROL_SOCK="$SOCKET_DIR/control.sock"
readonly CH_BIN="${CLOUD_HYPERVISOR:-cloud-hypervisor}"
readonly BASE_IMAGE="${K8NETD_E2E_IMAGE:-}"
# CH has no built-in BIOS: disk boots go through the EDK2 firmware shipped
# alongside the base image (k8labs build layout).
readonly FIRMWARE="${K8NETD_E2E_FIRMWARE:-$(dirname "$BASE_IMAGE")/CLOUDHV.fd}"
# Private half of the key baked into the base image's root authorized_keys
# (k8labs packer-ssh-key; its public half ships beside the image as
# ssh-lab.pub).
_default_ssh_key="$(dirname "$BASE_IMAGE")/packer-ssh-key"
[[ -f "$_default_ssh_key" ]] || _default_ssh_key=/home/eryoma/workspace/k8labs/build/packer-ssh-key
readonly SSH_KEY="${K8NETD_E2E_SSH_KEY:-$_default_ssh_key}"
readonly TIMEOUT_S=150

log() { printf '[e2e] %s\n' "$*"; }
die() { printf '[e2e] FAIL: %s\n' "$*" >&2; exit 1; }
skip() { printf '[e2e] SKIP: %s\n' "$*" >&2; exit 77; }
# Kill everything this run spawned: leaked cloud-hypervisor children hold an
# ExclusiveWrite flock on the base image and poison every later run.
cleanup() {
	[[ -n "${LOCAL_CH_A:-}" ]] && kill "$LOCAL_CH_A" 2>/dev/null
	[[ -n "${LOCAL_CH_B:-}" ]] && kill "$LOCAL_CH_B" 2>/dev/null
	[[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null
	true
}
trap cleanup EXIT

# --- prerequisites (gate 0) ------------------------------------------------
command -v "$CH_BIN" >/dev/null 2>&1 || skip "cloud-hypervisor not installed"
command -v passt >/dev/null 2>&1 || skip "passt not installed"
[[ -n "$BASE_IMAGE" && -f "$BASE_IMAGE" ]] || skip "base image not set (K8NETD_E2E_IMAGE)"
[[ -f "$FIRMWARE" ]] || skip "CH firmware not found at $FIRMWARE"
[[ -w /dev/kvm ]] || skip "/dev/kvm not accessible"
command -v python3 >/dev/null 2>&1 || skip "python3 needed for JSON-RPC client"
command -v qemu-img >/dev/null 2>&1 || skip "qemu-img needed for per-VM disk images"
[[ -f "$SSH_KEY" ]] || skip "image ssh private key not found (K8NETD_E2E_SSH_KEY)"

# --- system-under-test selection (grill D9) --------------------------------
# Quadlet mode: when the user unit is active, exercise the real deployment
# shape (image + unit) instead of a hand-launched binary. The socket dir then
# comes from the unit's Environment pin; K8NETD_SOCKET_DIR is ignored.
SUT_MODE=binary
if systemctl --user is-active --quiet k8netd 2>/dev/null; then
	SUT_MODE=quadlet
	log "SUT: quadlet-managed k8netd.service"
else
	log "SUT: hand-launched binary"
fi

# --- build (binary mode only) ----------------------------------------------
if [[ "$SUT_MODE" == binary ]]; then
	log "building workspace"
	cargo build --release --workspace || die "cargo build"
fi

# --- step 1: daemon up, control socket answers -----------------------------
if [[ "$SUT_MODE" == quadlet ]]; then
	SOCKET_DIR="$(systemctl --user show k8netd -p Environment --value | tr ' ' '\n' | grep '^K8NETD_SOCKET_DIR=' | cut -d= -f2-)"
	[[ -n "$SOCKET_DIR" ]] || die "quadlet unit does not pin K8NETD_SOCKET_DIR"
	log "using quadlet socket dir $SOCKET_DIR"
else
	log "starting k8netd at $SOCKET_DIR"
	K8NETD_SOCKET_DIR="$SOCKET_DIR" ./target/release/k8netd &
	DAEMON_PID=$!
fi
for _ in $(seq 1 50); do
	[[ -S "$CONTROL_SOCK" ]] && break
	sleep 0.1
done
[[ -S "$CONTROL_SOCK" ]] || die "control socket never appeared"

rpc() { # rpc <method> <params-json>
	python3 - "$CONTROL_SOCK" "$1" "$2" <<'PY'
import json, socket, sys
path, method, params = sys.argv[1], sys.argv[2], sys.argv[3]
req = json.dumps({"jsonrpc": "2.0", "version": "1.0", "method": method,
                  "params": json.loads(params), "id": 1})
with socket.socket(socket.AF_UNIX) as s:
    s.connect(path)
    s.sendall((req + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
resp = json.loads(buf.decode())
if "error" in resp:
    sys.exit(f"RPC error: {resp['error']}")
print(json.dumps(resp.get("result")))
PY
}

# --- step 2: topology ------------------------------------------------------
log "creating network + ports"
rpc CreateNetwork '{"name":"net0","cidr":"192.168.124.0/24","gateway":"192.168.124.1","poolStart":"192.168.124.100","poolEnd":"192.168.124.200"}' >/dev/null
rpc CreatePort '{"name":"vm-a"}' >/dev/null
rpc CreatePort '{"name":"vm-b"}' >/dev/null
rpc AttachPort '{"port":"vm-a","network":"net0","mac":"02:00:00:00:00:01"}' >/dev/null
rpc AttachPort '{"port":"vm-b","network":"net0","mac":"02:00:00:00:00:02"}' >/dev/null
[[ -S "$SOCKET_DIR/vm-a.sock" ]] || die "vhost-user socket vm-a.sock missing"
[[ -S "$SOCKET_DIR/vm-b.sock" ]] || die "vhost-user socket vm-b.sock missing"

# --- steps 3-5: boot VMs, verify connectivity + forward --------------------
# Boot commands are lab-specific; the image must run DHCP and expose ssh.
# Each VM gets its own converted copy of the base image: cloud-hypervisor
# takes an ExclusiveWrite flock on every writable disk (two VMs cannot share
# one image file) and its qcow2 parser rejects backing chains (no overlays).
log "creating per-VM disk images"
qemu-img convert -O qcow2 "$BASE_IMAGE" "$SOCKET_DIR/vm-a.qcow2"
qemu-img convert -O qcow2 "$BASE_IMAGE" "$SOCKET_DIR/vm-b.qcow2"
log "booting VM-A"
"$CH_BIN" \
	--cpus boot=2 --memory size=512M,shared=on \
	--disk path="$SOCKET_DIR/vm-a.qcow2" \
	--firmware "$FIRMWARE" \
	--net vhost_user=true,socket="$SOCKET_DIR/vm-a.sock",num_queues=2,mac="02:00:00:00:00:01" \
	--cmdline "console=ttyS0 root=/dev/vda rw" \
	>"$SOCKET_DIR/vm-a.log" 2>&1 &
LOCAL_CH_A=$!
log "booting VM-B"
"$CH_BIN" \
	--cpus boot=2 --memory size=512M,shared=on \
	--disk path="$SOCKET_DIR/vm-b.qcow2" \
	--firmware "$FIRMWARE" \
	--net vhost_user=true,socket="$SOCKET_DIR/vm-b.sock",num_queues=2,mac="02:00:00:00:00:02" \
	--cmdline "console=ttyS0 root=/dev/vda rw" \
	>"$SOCKET_DIR/vm-b.log" 2>&1 &
LOCAL_CH_B=$!

# Fail fast when a CH instance died at startup (e.g. image lock held by a
# leaked process from an earlier run) instead of waiting out the DHCP gate.
sleep 2
kill -0 "$LOCAL_CH_A" 2>/dev/null || { tail -5 "$SOCKET_DIR/vm-a.log" >&2; die "VM-A cloud-hypervisor exited during boot"; }
kill -0 "$LOCAL_CH_B" 2>/dev/null || { tail -5 "$SOCKET_DIR/vm-b.log" >&2; die "VM-B cloud-hypervisor exited during boot"; }

SSH_OPTS=(-o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes -i "$SSH_KEY")

# The guest network lives entirely in k8netd's userspace dataplane: the lab
# host has no kernel route into 192.168.124.0/24. The only host->guest path
# is a published forward to the guest's sshd (REQ-008/REQ-010), which this
# gate setup exercises on purpose.
log "publishing VM-A ssh forward"
SSH_FWD=$(rpc PublishPort '{"port":"vm-a","vm_port":22}')
SSH_PORT=$(printf '%s' "$SSH_FWD" | python3 -c 'import json,sys; print(json.load(sys.stdin)["host_port"])')
[[ -n "$SSH_PORT" ]] || die "PublishPort returned no host_port for ssh"
log "ssh forward: 127.0.0.1:$SSH_PORT -> vm-a:22"

log "publishing VM-B ssh forward"
SSH_FWD_B=$(rpc PublishPort '{"port":"vm-b","vm_port":22}')
SSH_PORT_B=$(printf '%s' "$SSH_FWD_B" | python3 -c 'import json,sys; print(json.load(sys.stdin)["host_port"])')
[[ -n "$SSH_PORT_B" ]] || die "PublishPort returned no host_port for vm-b ssh"
log "ssh forward: 127.0.0.1:$SSH_PORT_B -> vm-b:22"

vm_ssh() { # vm_ssh <command...>
	ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" root@127.0.0.1 "$@"
}

vm_ssh_b() { # vm_ssh_b <command...> — VM-B via its published ssh forward
	ssh "${SSH_OPTS[@]}" -p "$SSH_PORT_B" root@127.0.0.1 "$@"
}

wait_vm_ssh() { # wait_vm_ssh — ssh via the published forward
	for _ in $(seq 1 "$TIMEOUT_S"); do
		vm_ssh true 2>/dev/null && return 0
		sleep 1
	done
	return 1
}

wait_vm_b() { # wait_vm_b — VM-B is up once it answers pings from VM-A
	for _ in $(seq 1 "$TIMEOUT_S"); do
		vm_ssh "ping -c1 -W1 192.168.124.101" >/dev/null 2>&1 && return 0
		sleep 1
	done
	return 1
}

log "waiting for DHCP on both VMs"
wait_vm_ssh || die "VM-A never got a lease / ssh"
wait_vm_b || die "VM-B never got a lease / pingable"

log "gate: VM-A -> VM-B ping"
vm_ssh "ping -c2 192.168.124.101" || die "east-west ping failed"

log "gate: VM-A -> gateway ping"
vm_ssh "ping -c2 192.168.124.1" || die "gateway ping failed"

log "gate: VM-A -> pod-CIDR frame via VM-B stays on the L2 fabric (REQ-007)"
# Regression (MAC-based egress): a frame with a destination IP outside the
# network CIDR (pod-CIDR 10.244.x) that VM-A routes to peer VM-B's MAC must
# be L2-forwarded to VM-B, never sent to VM-A's passt (WAN). VM-B hosts
# 10.244.0.1 on a dummy interface so the ping completes only when the frame
# is L2-forwarded; under the old dst-IP classifier k8netd would send it to
# the WAN and the ping would time out.
vm_ssh_b "ip link add dummy0 type dummy 2>/dev/null; ip addr add 10.244.0.1/32 dev dummy0 2>/dev/null; ip link set dummy0 up"
vm_ssh "ip route add 10.244.0.1/32 via 192.168.124.101 2>/dev/null; ping -c2 10.244.0.1" || die "pod-CIDR L2 forwarding failed"
vm_ssh_b "ip link del dummy0" || true

log "publishing VM-A 6443 forward"
PUBLISH_OUT=$(rpc PublishPort '{"port":"vm-a","vm_port":6443}')
HOST_PORT=$(printf '%s' "$PUBLISH_OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["host_port"])')
[[ -n "$HOST_PORT" ]] || die "PublishPort returned no host_port"
log "host forward: 127.0.0.1:$HOST_PORT -> vm-a:6443"

log "gate: internet egress through per-VM passt"
vm_ssh "curl -fsS --max-time 10 http://example.com >/dev/null" || die "egress failed"

log "gate: host port-forward $HOST_PORT -> VM-A"
vm_ssh "nc -l -p 6443 & sleep 5; kill \$!" >/dev/null 2>&1 &
NC_PID=$!
sleep 1
timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$HOST_PORT" || {
	kill "$NC_PID" 2>/dev/null
	die "$HOST_PORT forward unreachable"
}
kill "$NC_PID" 2>/dev/null
wait "$NC_PID" 2>/dev/null || true
true

# --- step 6: restart gate (REQ-010, 60s window) ----------------------------
log "restart gate: killing daemon and restarting within ${TIMEOUT_S}s"
if [[ "$SUT_MODE" == quadlet ]]; then
	# SIGKILL the daemon; systemd Restart=always resurrects it and REQ-010
	# re-binds the sockets from persisted state.
	kill -9 "$(systemctl --user show k8netd -p MainPID --value)" 2>/dev/null || true
else
	kill -9 "$DAEMON_PID" 2>/dev/null || true
	unset DAEMON_PID
	K8NETD_SOCKET_DIR="$SOCKET_DIR" ./target/release/k8netd &
	DAEMON_PID=$!
fi

restart_deadline=$((SECONDS + TIMEOUT_S))
until [[ -S "$CONTROL_SOCK" ]]; do
	((SECONDS < restart_deadline)) || die "daemon did not re-listen within ${TIMEOUT_S}s"
	sleep 0.5
done
rpc CreateNetwork '{"name":"net0","cidr":"192.168.124.0/24","gateway":"192.168.124.1","poolStart":"192.168.124.100","poolEnd":"192.168.124.200"}' >/dev/null
rpc CreatePort '{"name":"vm-a"}' >/dev/null
rpc AttachPort '{"port":"vm-a","network":"net0","mac":"02:00:00:00:00:01"}' >/dev/null
# Re-create VM-B's port too so its still-running frontend can rejoin the
# switch; otherwise the east-west ping below has no peer to reach.
rpc CreatePort '{"name":"vm-b"}' >/dev/null
rpc AttachPort '{"port":"vm-b","network":"net0","mac":"02:00:00:00:00:02"}' >/dev/null
# Re-ensure the ssh forward: the publish table survives the restart from
# state.json (same allocation), but the passt subprocess must be respawned.
rpc PublishPort '{"port":"vm-a","vm_port":22}' >/dev/null
sleep 2
vm_ssh "ping -c2 192.168.124.101" || die "connectivity lost after restart"

kill "$LOCAL_CH_A" "$LOCAL_CH_B" 2>/dev/null || true
log "PASS: all VC-09 gates green"
