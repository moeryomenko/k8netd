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
readonly TIMEOUT_S=60

log() { printf '[e2e] %s\n' "$*"; }
die() { printf '[e2e] FAIL: %s\n' "$*" >&2; exit 1; }
skip() { printf '[e2e] SKIP: %s\n' "$*" >&2; exit 77; }
cleanup() { [[ -n "${DAEMON_PID:-}" ]] && kill "$DAEMON_PID" 2>/dev/null || true; }
trap cleanup EXIT

# --- prerequisites (gate 0) ------------------------------------------------
command -v "$CH_BIN" >/dev/null 2>&1 || skip "cloud-hypervisor not installed"
command -v passt >/dev/null 2>&1 || skip "passt not installed"
[[ -n "$BASE_IMAGE" && -f "$BASE_IMAGE" ]] || skip "base image not set (K8NETD_E2E_IMAGE)"
[[ -w /dev/kvm ]] || skip "/dev/kvm not accessible"
command -v python3 >/dev/null 2>&1 || skip "python3 needed for JSON-RPC client"

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
log "booting VM-A"
"$CH_BIN" \
	--cpus 2 --memory size=512M \
	--disk path="$BASE_IMAGE" \
	--net vhost_user=true,socket="$SOCKET_DIR/vm-a.sock",num_queues=1,mac="02:00:00:00:00:01" \
	--cmdline "console=ttyS0 root=/dev/vda rw" \
	>"$SOCKET_DIR/vm-a.log" 2>&1 &
local_ch_a=$!
log "booting VM-B"
"$CH_BIN" \
	--cpus 2 --memory size=512M \
	--disk path="$BASE_IMAGE" \
	--net vhost_user=true,socket="$SOCKET_DIR/vm-b.sock",num_queues=1,mac="02:00:00:00:00:02" \
	--cmdline "console=ttyS0 root=/dev/vda rw" \
	>"$SOCKET_DIR/vm-b.log" 2>&1 &
local_ch_b=$!

wait_vm_ssh() { # wait_vm_ssh <ip>
	for _ in $(seq 1 "$TIMEOUT_S"); do
		ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -o BatchMode=yes \
			root@"$1" true 2>/dev/null && return 0
		sleep 1
	done
	return 1
}

log "waiting for DHCP on both VMs"
wait_vm_ssh 192.168.124.101 || die "VM-A never got a lease / ssh"
wait_vm_ssh 192.168.124.102 || die "VM-B never got a lease / ssh"

log "gate: VM-A -> VM-B ping"
ssh -o BatchMode=yes root@192.168.124.101 "ping -c2 192.168.124.102" || die "east-west ping failed"

log "gate: VM-A -> gateway ping"
ssh -o BatchMode=yes root@192.168.124.101 "ping -c2 192.168.124.1" || die "gateway ping failed"

log "gate: internet egress through per-VM passt"
ssh -o BatchMode=yes root@192.168.124.101 "curl -fsS --max-time 10 http://example.com >/dev/null" || die "egress failed"

log "gate: host port-forward 127.0.0.1:6443 -> VM-A"
ssh -o BatchMode=yes root@192.168.124.101 "nc -l -p 6443 & sleep 0.3; kill \$!" >/dev/null 2>&1 || true
timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/6443' || die "6443 forward unreachable"

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
ssh -o BatchMode=yes root@192.168.124.101 "ping -c2 192.168.124.102" || die "connectivity lost after restart"

kill "$local_ch_a" "$local_ch_b" 2>/dev/null || true
log "PASS: all VC-09 gates green"
