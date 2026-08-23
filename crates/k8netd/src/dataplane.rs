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
use k8netd_core::model::{IpPool, MacAddr};
use k8netd_core::switch::engine::Switch;
use k8netd_core::switch::mac_table::PortId;
use k8netd_rpc::protocol::RpcError;
use k8netd_rpc::server::ControlPlane;
use k8netd_vhost::port::{PortMessage, PortSink, VhostPort};
use serde_json::{Value, json};

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
    pub fn new(socket_dir: impl Into<PathBuf>) -> Self {
        Dataplane {
            socket_dir: socket_dir.into(),
            inner: Arc::new(Mutex::new(Inner {
                networks: BTreeMap::new(),
                ports: BTreeMap::new(),
                names: BTreeMap::new(),
                switch: Switch::new(),
            })),
        }
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
        Ok(Value::Null)
    }

    fn allocate_ip(&mut self, params: &Value) -> Result<Value, RpcError> {
        let net = str_p(params, "network")?.to_string();
        let mac: MacAddr = str_p(params, "mac")?.parse().map_err(|_| RpcError::InvalidParams)?;
        let mut g = lock(&self.inner)?;
        let e = g.networks.get_mut(&net).ok_or(RpcError::NotFound)?;
        let ip = e.ipam.allocate(mac).map_err(ipam_err)?;
        Ok(json!({ "ip": ip.to_string() }))
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
}

// -- helpers ---------------------------------------------------------------

#[allow(dead_code)]
fn str_p<'a>(params: &'a Value, key: &str) -> Result<&'a str, RpcError> {
    params.get(key).and_then(Value::as_str).ok_or(RpcError::InvalidParams)
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
    use k8netd_vhost::fake_frontend::FakeFrontend;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn net_params() -> Value {
        serde_json::json!({
            "name": "net0", "cidr": "192.168.124.0/24", "gateway": "192.168.124.1",
            "poolStart": "192.168.124.100", "poolEnd": "192.168.124.200"
        })
    }

    /// TASK-030 / VC-07: two live ports on one network; a broadcast frame
    /// emitted by VM-A must be flooded to VM-B through the full stack
    /// (virtqueue -> pump -> switch -> virtqueue).
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

        // VM-A emits a broadcast frame (driver side of port 1).
        let frame = vec![0xffu8; 60];
        let addr = 0x1000_0000u64 + 0x3_0000; // DATA_OFFSET scratch area
        vm_memory::Bytes::write_slice(fe1.mem(), &frame, vm_memory::GuestAddress(addr))?;
        write_desc_and_kick(fe1.mem(), fe1.kick_fd(), addr, frame.len() as u32)?;

        // VM-B posts a device-writable RX buffer first (driver side of port 2).
        let rx_addr = 0x1000_0000u64 + 0x3_0000 + 0x1000;
        vm_memory::Bytes::write_slice(fe2.mem(), &[0u8; 128], vm_memory::GuestAddress(rx_addr))?;
        post_rx_and_kick(fe2.mem(), fe2.kick_fd(), rx_addr)?;

        // VM-B must receive it in a used writable buffer.
        let got = wait_frame(fe2.mem(), Duration::from_secs(5))?;
        assert_eq!(got, frame, "broadcast must arrive intact at the peer");

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    // -- minimal driver-side helpers (mirror port.rs test utilities) -------

    const DESC_TABLE: u64 = 0x0;
    const AVAIL_RING: u64 = 0x2_0000;
    const QUEUE_SIZE: u16 = 256;

    fn write_desc_and_kick(
        mem: &vm_memory::GuestMemoryMmap<()>,
        kick_fd: RawFd,
        buf_addr: u64,
        len: u32,
    ) -> TestResult {
        use vm_memory::{Bytes, GuestAddress};
        let base = 0x1000_0000u64;
        // desc 5 (arbitrary free slot): readable buffer at buf_addr.
        let d = base + DESC_TABLE + 5 * 16;
        mem.write_obj(buf_addr.to_le_bytes(), GuestAddress(d))?;
        mem.write_obj(len.to_le_bytes(), GuestAddress(d + 8))?;
        mem.write_obj(0u16.to_le_bytes(), GuestAddress(d + 12))?; // no flags
        mem.write_obj(0u16.to_le_bytes(), GuestAddress(d + 14))?;
        // avail ring: append idx 5.
        let idx_addr = GuestAddress(base + AVAIL_RING + 2);
        let cur: u16 = mem.read_obj(idx_addr)?;
        let slot = GuestAddress(base + AVAIL_RING + 4 + u64::from(cur % QUEUE_SIZE) * 2);
        mem.write_obj(5u16.to_le_bytes(), slot)?;
        mem.write_obj((cur + 1).to_le_bytes(), idx_addr)?;
        // kick.
        let val: u64 = 1;
        let n = unsafe { libc::write(kick_fd, &val as *const u64 as *const libc::c_void, 8) };
        assert_eq!(n, 8);
        Ok(())
    }

    /// Polls the used ring for desc 5 and returns the written payload from
    /// the descriptor's buffer address.
    fn wait_frame(
        mem: &vm_memory::GuestMemoryMmap<()>,
        timeout: Duration,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use vm_memory::{Bytes, GuestAddress};
        let base = 0x1000_0000u64;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if std::time::Instant::now() > deadline {
                panic!("frame never arrived at peer");
            }
            let used_idx: u16 = mem.read_obj(GuestAddress(base + 0x1_0000 + 2))?;
            if used_idx > 0 {
                // Used elem 0 -> (desc id, len); read len bytes back from the
                // buffer that desc 5 pointed at.
                let id: u32 = mem.read_obj(GuestAddress(base + 0x1_0000 + 4))?;
                let len: u32 = mem.read_obj(GuestAddress(base + 0x1_0000 + 8))?;
                let _ = id;
                let mut buf = vec![0u8; len as usize];
                mem.read_slice(&mut buf, GuestAddress(base + 0x3_0000 + 0x1000))?;
                return Ok(buf);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    use std::os::fd::RawFd;
    use std::time::Duration;

    /// Posts one device-writable descriptor (idx 6) at `buf_addr` and kicks.
    fn post_rx_and_kick(mem: &vm_memory::GuestMemoryMmap<()>, kick_fd: RawFd, buf_addr: u64) -> TestResult {
        use vm_memory::{Bytes, GuestAddress};
        let base = 0x1000_0000u64;
        let d = base + DESC_TABLE + 6 * 16;
        mem.write_obj(buf_addr.to_le_bytes(), GuestAddress(d))?;
        mem.write_obj(128u32.to_le_bytes(), GuestAddress(d + 8))?;
        mem.write_obj(2u16.to_le_bytes(), GuestAddress(d + 12))?; // VIRTQ_DESC_F_WRITE
        mem.write_obj(0u16.to_le_bytes(), GuestAddress(d + 14))?;
        let idx_addr = GuestAddress(base + AVAIL_RING + 2);
        let cur: u16 = mem.read_obj(idx_addr)?;
        let slot = GuestAddress(base + AVAIL_RING + 4 + u64::from(cur % QUEUE_SIZE) * 2);
        mem.write_obj(6u16.to_le_bytes(), slot)?;
        mem.write_obj((cur + 1).to_le_bytes(), idx_addr)?;
        let val: u64 = 1;
        let n = unsafe { libc::write(kick_fd, &val as *const u64 as *const libc::c_void, 8) };
        assert_eq!(n, 8);
        Ok(())
    }
}
