//! Dataplane orchestration: wires the control plane to live vhost-user
//! ports and the L2 switch engine (spec REQ-003, REQ-007; plan TASK-030/031).
//!
//! `Dataplane` implements [`ControlPlane`]: CreatePort binds a real Unix
//! socket (`VhostPort`) plus channel ends; AttachPort joins the port into the
//! switch engine and reserves an IP; one pump thread per port moves frames
//! from the virtqueue through [`Switch::forward`] and injects the flooded /
//! forwarded copies into the peers' virtqueues.
//!
//! DHCP/DNS gateway handling and passt WAN egress hook in at the pump level
//! in later wiring; this module keeps those seams explicit.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use k8netd_core::ipam::{Ipam, IpamError};
use k8netd_core::model::{IpPool, MacAddr, PublishTable};
use k8netd_core::switch::engine::Switch;
use k8netd_core::switch::mac_table::PortId;
use k8netd_rpc::protocol::RpcError;
use k8netd_rpc::server::ControlPlane;
use k8netd_vhost::port::{PortMessage, PortSink, VhostPort};
use serde_json::{Value, json};

/// Default inclusive host-port range for the PublishPort allocator
/// (REQ-010); mirrors the config default.
const DEFAULT_PUBLISH_RANGE: (u16, u16) = (20_000, 21_000);

/// A live port: control state plus the injection end for its virtqueue.
/// The delivery end is owned exclusively by the port's pump thread.
#[allow(dead_code)] // constructed via ControlPlane impl (bin crate)
struct LivePort {
    network: Option<String>,
    mac: Option<MacAddr>,
    /// Switch -> port: ToVm frames destined for this VM.
    inject: Sender<PortMessage>,
}

#[allow(dead_code)] // constructed via ControlPlane impl (bin crate)
struct NetworkEntry {
    ipam: Ipam,
    created_with: Value,
}

#[allow(dead_code)]
struct Inner {
    networks: BTreeMap<String, NetworkEntry>,
    ports: BTreeMap<String, LivePort>,
    /// Switch PortId -> port name, so pumps can resolve flood targets.
    names: BTreeMap<u32, String>,
    switch: Switch,
    /// Inclusive host-port range the publish allocator hands out (REQ-010).
    publish_range: (u16, u16),
    /// Published inbound-forward allocations keyed by port name (REQ-010).
    publish_table: PublishTable,
}

/// The full dataplane: control-plane semantics + live frame forwarding.
#[allow(dead_code)] // wired into main.rs with TASK-031 runtime
pub struct Dataplane {
    socket_dir: PathBuf,
    inner: Arc<Mutex<Inner>>,
}

#[allow(dead_code)] // wired into main.rs with TASK-031 runtime
impl Dataplane {
    /// Creates a dataplane rooted at `socket_dir`; port sockets land here.
    ///
    /// Restores the persisted publish table (REQ-010) so allocations survive
    /// a daemon restart; a missing or unreadable state file starts empty.
    pub fn new(socket_dir: impl Into<PathBuf>) -> Self {
        let socket_dir = socket_dir.into();
        let publish_table = k8netd_core::state::load_from_disk(&socket_dir)
            .map(|store| store.publish_table)
            .unwrap_or_default();
        Dataplane {
            socket_dir,
            inner: Arc::new(Mutex::new(Inner {
                networks: BTreeMap::new(),
                ports: BTreeMap::new(),
                names: BTreeMap::new(),
                switch: Switch::new(),
                publish_range: DEFAULT_PUBLISH_RANGE,
                publish_table,
            })),
        }
    }

    /// Persists the publish table to `state.json` (REQ-010 atomic save).
    fn persist(&self, inner: &Inner) -> Result<(), RpcError> {
        let store = k8netd_core::state::StateStore {
            publish_table: inner.publish_table.clone(),
            ..k8netd_core::state::StateStore::default()
        };
        k8netd_core::state::save_to_disk(&store, &self.socket_dir).map_err(|_| RpcError::Internal)
    }

    /// Spawns the per-port pump: FromVm frames are learned + forwarded via
    /// the core switch engine; each flooded copy is injected into the target
    /// port's virtqueue.
    fn spawn_pump(name: String, deliver: Receiver<PortMessage>, inner: Arc<Mutex<Inner>>) {
        thread::spawn(move || {
            while let Ok(msg) = deliver.recv() {
                let PortMessage::FromVm(frame) = msg else { continue };
                let targets: Vec<(String, Vec<u8>)> = {
                    let mut g = match inner.lock() {
                        Ok(g) => g,
                        Err(_) => continue,
                    };
                    let me = port_num(&name);
                    g.switch
                        .forward(PortId(me), &frame)
                        .into_iter()
                        .filter(|(pid, _)| pid.0 != me)
                        // Resolve the numeric switch id back to the port name.
                        .filter_map(|(pid, f)| g.names.get(&pid.0).map(|n| (n.clone(), f.to_vec())))
                        .collect()
                };
                for (peer, f) in targets {
                    // Scope the guard so the borrow cannot escape.
                    let sent = match inner.lock() {
                        Ok(g) => g
                            .ports
                            .get(&peer)
                            .map(|lp| lp.inject.send(PortMessage::ToVm(f)).is_ok())
                            .unwrap_or(false),
                        Err(_) => false,
                    };
                    let _ = sent;
                }
            }
        });
    }
}

/// Ports are numbered by creation order inside the switch; derive a stable
/// numeric id from the trailing digits of the port name (e.g. "vm7" -> 7).
#[allow(dead_code)]
fn port_num(name: &str) -> u32 {
    name.chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

impl ControlPlane for Dataplane {
    fn create_network(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?.to_string();
        let cidr = str_p(params, "cidr")?;
        let gateway = str_p(params, "gateway")?;
        let pool_start = str_p(params, "poolStart")?;
        let pool_end = str_p(params, "poolEnd")?;

        let mut g = lock(&self.inner)?;
        if let Some(e) = g.networks.get(&name) {
            return if e.created_with == *params {
                Ok(Value::Null)
            } else {
                Err(RpcError::Conflict)
            };
        }
        let pool = IpPool::new(
            pool_start.parse().map_err(|_| RpcError::InvalidParams)?,
            pool_end.parse().map_err(|_| RpcError::InvalidParams)?,
        )
        .map_err(|_| RpcError::InvalidParams)?;
        let network =
            k8netd_core::model::Network::new(&name, cidr, gateway, pool).map_err(|_| RpcError::InvalidParams)?;
        let ipam = Ipam::new(network);
        g.networks.insert(
            name,
            NetworkEntry {
                ipam,
                created_with: params.clone(),
            },
        );
        Ok(Value::Null)
    }

    fn delete_network(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?;
        let mut g = lock(&self.inner)?;
        g.networks.remove(name).map(|_| Value::Null).ok_or(RpcError::NotFound)
    }

    fn get_network(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?;
        let g = lock(&self.inner)?;
        let e = g.networks.get(name).ok_or(RpcError::NotFound)?;
        Ok(json!({
            "name": name,
            "cidr": e.ipam.network().cidr.to_string(),
            "gateway": e.ipam.network().gateway.to_string(),
        }))
    }

    fn create_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?.to_string();
        let sock = self.socket_dir.join(format!("{name}.sock"));
        let mut g = lock(&self.inner)?;
        if g.ports.contains_key(&name) {
            return Ok(Value::Null); // idempotent (REQ-001/REQ-003)
        }
        // Channel ends: the port consumes inject_rx / produces on deliver_tx;
        // the test/switch side keeps their counterparts.
        let (_inject_tx_for_test, inject_rx) = std::sync::mpsc::channel::<PortMessage>();
        let (deliver_tx, deliver_rx) = std::sync::mpsc::channel::<PortMessage>();
        VhostPort::new(
            &sock,
            &name,
            PortSink {
                tx: deliver_tx,
                rx: inject_rx,
            },
        )
        .map_err(|_| RpcError::Internal)?;
        // The pump owns the delivery end exclusively.
        Dataplane::spawn_pump(name.clone(), deliver_rx, Arc::clone(&self.inner));
        let num = port_num(&name);
        g.switch.add_port(PortId(num), "");
        g.names.insert(num, name.clone());
        g.ports.insert(
            name,
            LivePort {
                network: None,
                mac: None,
                inject: _inject_tx_for_test,
            },
        );
        Ok(Value::Null)
    }

    fn delete_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?;
        let mut g = lock(&self.inner)?;
        match g.ports.remove(name) {
            Some(_) => {
                let num = port_num(name);
                g.switch.remove_port(PortId(num));
                g.names.remove(&num);
                // REQ-010: deleting the owning port frees its allocations.
                g.publish_table.remove_port(name);
                self.persist(&g)?;
                // The socket file is removed with the port (REQ-003).
                let sock = self.socket_dir.join(format!("{name}.sock"));
                let _ = std::fs::remove_file(sock);
                Ok(Value::Null)
            }
            None => Err(RpcError::NotFound),
        }
    }

    fn get_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?;
        let g = lock(&self.inner)?;
        let p = g.ports.get(name).ok_or(RpcError::NotFound)?;
        Ok(json!({
            "name": name,
            "network": p.network,
            "mac": p.mac.map(|m| m.to_string()),
        }))
    }

    fn attach_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let port_name = str_p(params, "port")?.to_string();
        let net_name = str_p(params, "network")?.to_string();
        let mac: MacAddr = str_p(params, "mac")?.parse().map_err(|_| RpcError::InvalidParams)?;

        let mut g = lock(&self.inner)?;
        if !g.ports.contains_key(&port_name) {
            return Err(RpcError::NotFound);
        }
        {
            let e = g.networks.get_mut(&net_name).ok_or(RpcError::NotFound)?;
            // REQ-004: reserve before boot.
            e.ipam.allocate(mac).map_err(ipam_err)?;
        }
        let port = g.ports.get_mut(&port_name).expect("checked above");
        if port.network.as_deref() == Some(net_name.as_str()) && port.mac == Some(mac) {
            return Ok(Value::Null); // idempotent re-attach
        }
        if port.network.is_some() {
            return Err(RpcError::Conflict);
        }
        port.network = Some(net_name.clone());
        port.mac = Some(mac);
        g.switch.add_port(PortId(port_num(&port_name)), &net_name);
        Ok(Value::Null)
    }

    fn detach_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?;
        let mut g = lock(&self.inner)?;
        let p = g.ports.get_mut(name).ok_or(RpcError::NotFound)?;
        // Socket stays alive across detach (REQ-003); leave the L2 segment.
        p.network = None;
        p.mac = None;
        // REQ-010: detaching the owning port frees its published allocations.
        g.publish_table.remove_port(name);
        self.persist(&g)?;
        Ok(Value::Null)
    }

    fn allocate_ip(&mut self, params: &Value) -> Result<Value, RpcError> {
        let net = str_p(params, "network")?.to_string();
        let mac: MacAddr = str_p(params, "mac")?.parse().map_err(|_| RpcError::InvalidParams)?;
        let mut g = lock(&self.inner)?;
        let e = g.networks.get_mut(&net).ok_or(RpcError::NotFound)?;
        let ip = e.ipam.allocate(mac).map_err(ipam_err)?;
        // Contract: AllocateIP's result is a bare JSON string carrying the
        // address, not an object.
        Ok(Value::String(ip.to_string()))
    }

    fn release_ip(&mut self, params: &Value) -> Result<Value, RpcError> {
        let net = str_p(params, "network")?;
        let mac: MacAddr = str_p(params, "mac")?.parse().map_err(|_| RpcError::InvalidParams)?;
        let mut g = lock(&self.inner)?;
        let e = g.networks.get_mut(net).ok_or(RpcError::NotFound)?;
        e.ipam.release(mac).map_err(|err| match err {
            IpamError::UnknownMac => RpcError::NotFound,
            other => ipam_err(other),
        })?;
        Ok(Value::Null)
    }

    fn publish_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let port_name = str_p(params, "port")?;
        let vm_port = u16_p(params, "vm_port")?;

        let mut g = lock(&self.inner)?;
        // REQ-010: only attached ports are publishable; unknown and
        // unattached (including since-detached) ports are not_found.
        let attached = g.ports.get(port_name).map(|p| p.network.is_some()).unwrap_or(false);
        if !attached {
            return Err(RpcError::NotFound);
        }

        // Idempotent re-publish returns the recorded allocation unchanged.
        let range = g.publish_range;
        let host_port = match g.publish_table.get(port_name, vm_port) {
            Some(host) => host,
            None => g
                .publish_table
                .allocate(port_name, vm_port, range)
                .ok_or(RpcError::Conflict)?, // exhaustion; no partial state
        };
        self.persist(&g)?;
        Ok(json!({ "host_port": host_port }))
    }
}

// -- helpers ---------------------------------------------------------------

#[allow(dead_code)]
fn str_p<'a>(params: &'a Value, key: &str) -> Result<&'a str, RpcError> {
    params.get(key).and_then(Value::as_str).ok_or(RpcError::InvalidParams)
}

/// Extracts a `u16` parameter, rejecting values outside the u16 domain.
#[allow(dead_code)]
fn u16_p(params: &Value, key: &str) -> Result<u16, RpcError> {
    params
        .get(key)
        .and_then(Value::as_u64)
        .filter(|v| *v <= u64::from(u16::MAX))
        .map(|v| v as u16)
        .ok_or(RpcError::InvalidParams)
}

#[allow(dead_code)]
fn lock(inner: &Arc<Mutex<Inner>>) -> Result<std::sync::MutexGuard<'_, Inner>, RpcError> {
    inner.lock().map_err(|_| RpcError::Internal)
}

#[allow(dead_code)]
fn ipam_err(e: IpamError) -> RpcError {
    match e {
        IpamError::PoolExhausted => RpcError::Conflict,
        IpamError::UnknownMac => RpcError::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8netd_vhost::fake_frontend::{
        AVAIL_RING_OFFSET, DATA_OFFSET, DESC_TABLE_OFFSET, FakeFrontend, GUEST_BASE, QUEUE_SIZE, USED_RING_OFFSET,
        VRING_STRIDE,
    };
    use k8netd_vhost::port::{RX_VRING, TX_VRING};

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn net_params() -> Value {
        serde_json::json!({
            "name": "net0", "cidr": "192.168.124.0/24", "gateway": "192.168.124.1",
            "poolStart": "192.168.124.100", "poolEnd": "192.168.124.200"
        })
    }

    /// TASK-030 / VC-07 + P15-1: two live ports on one network; a broadcast
    /// frame emitted by VM-A on its TX vring (index 1) must flow through the
    /// full stack (TX virtqueue -> pump -> Switch::forward) and reach VM-B
    /// on its RX vring (index 0).
    #[test]
    fn broadcast_floods_between_two_live_ports() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = std::env::temp_dir().join(format!("k8netd-dp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;

        let mut dp = Dataplane::new(&dir);
        assert!(dp.create_network(&net_params()).is_ok());
        dp.create_port(&serde_json::json!({"name": "vm1"}))
            .map_err(|e| format!("{e:?}"))?;
        dp.create_port(&serde_json::json!({"name": "vm2"}))
            .map_err(|e| format!("{e:?}"))?;
        dp.attach_port(&serde_json::json!(
            {"port": "vm1", "network": "net0", "mac": "02:00:00:00:00:01"}
        ))
        .map_err(|e| format!("{e:?}"))?;
        dp.attach_port(&serde_json::json!(
            {"port": "vm2", "network": "net0", "mac": "02:00:00:00:00:02"}
        ))
        .map_err(|e| format!("{e:?}"))?;

        // Connect real vhost-user frontends to the ports' sockets.
        let fe1 = FakeFrontend::connect(dir.join("vm1.sock"))?;
        let fe2 = FakeFrontend::connect(dir.join("vm2.sock"))?;

        // VM-B posts a device-writable RX buffer on its RX vring first.
        let rx_addr = GUEST_BASE + DATA_OFFSET + 0x1000;
        vm_memory::Bytes::write_slice(fe2.mem(), &[0u8; 128], vm_memory::GuestAddress(rx_addr))?;
        post_desc_and_kick(fe2.mem(), fe2.kick_fd(RX_VRING), RX_VRING, 6, rx_addr, 128, 2)?;

        // VM-A emits a broadcast frame on its TX vring.
        let frame = vec![0xffu8; 60];
        let tx_addr = GUEST_BASE + DATA_OFFSET;
        vm_memory::Bytes::write_slice(fe1.mem(), &frame, vm_memory::GuestAddress(tx_addr))?;
        post_desc_and_kick(
            fe1.mem(),
            fe1.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            frame.len() as u32,
            0,
        )?;

        // VM-B must receive it in a used writable buffer on its RX vring.
        let got = wait_frame(fe2.mem(), rx_addr, Duration::from_secs(5))?;
        assert_eq!(got, frame, "broadcast must arrive intact at the peer");

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    // -- minimal driver-side helpers (mirror port.rs test utilities) -------

    /// Guest-physical base of vring `vring`'s ring area.
    fn vring_base(vring: usize) -> u64 {
        GUEST_BASE + u64::try_from(vring).expect("vring index fits u64") * VRING_STRIDE
    }

    /// Posts one descriptor (no NEXT chaining) into vring `vring`, appends it
    /// to that vring's avail ring, and rings the kick doorbell.
    fn post_desc_and_kick(
        mem: &vm_memory::GuestMemoryMmap<()>,
        kick_fd: RawFd,
        vring: usize,
        desc_idx: u16,
        buf_addr: u64,
        len: u32,
        flags: u16,
    ) -> TestResult {
        use vm_memory::{Bytes, GuestAddress};
        let d = vring_base(vring) + DESC_TABLE_OFFSET + u64::from(desc_idx) * 16;
        mem.write_obj(buf_addr.to_le_bytes(), GuestAddress(d))?;
        mem.write_obj(len.to_le_bytes(), GuestAddress(d + 8))?;
        mem.write_obj(flags.to_le_bytes(), GuestAddress(d + 12))?;
        mem.write_obj(0u16.to_le_bytes(), GuestAddress(d + 14))?;
        let avail = vring_base(vring) + AVAIL_RING_OFFSET;
        let idx_addr = GuestAddress(avail + 2);
        let cur: u16 = mem.read_obj(idx_addr)?;
        let slot = GuestAddress(avail + 4 + u64::from(cur % QUEUE_SIZE) * 2);
        mem.write_obj(desc_idx.to_le_bytes(), slot)?;
        mem.write_obj((cur + 1).to_le_bytes(), idx_addr)?;
        let val: u64 = 1;
        let n = unsafe { libc::write(kick_fd, &val as *const u64 as *const libc::c_void, 8) };
        assert_eq!(n, 8);
        Ok(())
    }

    /// Polls the RX vring's used ring for the first completion and returns
    /// the payload written at `buf_addr`.
    fn wait_frame(
        mem: &vm_memory::GuestMemoryMmap<()>,
        buf_addr: u64,
        timeout: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use vm_memory::{Bytes, GuestAddress};
        let used_ring = vring_base(RX_VRING) + USED_RING_OFFSET;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if std::time::Instant::now() > deadline {
                panic!("frame never arrived at peer");
            }
            let used_idx: u16 = mem.read_obj(GuestAddress(used_ring + 2))?;
            if used_idx > 0 {
                // Used elem 0 -> (desc id, len); read len bytes back from
                // the buffer the posted RX descriptor pointed at.
                let id: u32 = mem.read_obj(GuestAddress(used_ring + 4))?;
                let len: u32 = mem.read_obj(GuestAddress(used_ring + 8))?;
                let _ = id;
                let mut buf = vec![0u8; len as usize];
                mem.read_slice(&mut buf, GuestAddress(buf_addr))?;
                return Ok(buf);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    use std::os::fd::RawFd;
    use std::time::Duration;
}
