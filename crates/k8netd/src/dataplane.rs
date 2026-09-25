//! Dataplane orchestration: wires the control plane to live vhost-user
//! ports and the L2 switch engine (spec REQ-003, REQ-007; plan TASK-030/031).
//!
//! `Dataplane` implements [`ControlPlane`]: CreatePort binds a real Unix
//! socket (`VhostPort`) plus channel ends; AttachPort joins the port into the
//! switch engine and reserves an IP; one pump thread per port moves frames
//! from the virtqueue through [`Switch::forward`] and injects the flooded /
//! forwarded copies into the peers' virtqueues.
//!
//! The pump is also where the four wiring seams live (TASK-004):
//! - PublishPort ensures a per-port passt WAN subprocess ([`PasstSlot`]) with
//!   the pinned argv contract; DeletePort/DetachPort stop it; a supervisor in
//!   each pump re-ensures an unexpectedly exited passt with bounded backoff.
//! - Gateway frames (ARP to the gateway IP, out-of-CIDR IPv4 egress) are
//!   answered locally or written vnet-framed to that port's passt fd; frames
//!   read back from passt are injected into the owning port's virtqueue by a
//!   dedicated reader thread.
//! - DHCP (UDP 68->67) and DNS-to-gateway-IP (UDP ->53) are intercepted
//!   before WAN/L2 classification: DHCP is answered from the network's IPAM
//!   reservations, DNS is relayed through the configured upstreams.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use k8netd_core::ipam::{Ipam, IpamError};
use k8netd_core::model::{IpPool, MacAddr, PublishTable};
use k8netd_core::state::{IpamSnapshot, NetworkState, PortState, StateStore};
use k8netd_core::switch::engine::Switch;
use k8netd_core::switch::gateway::{Gateway, GatewayAction};
use k8netd_core::switch::mac_table::PortId;
use k8netd_rpc::protocol::RpcError;
use k8netd_rpc::server::ControlPlane;
use k8netd_svc::dhcp::DhcpServer;
use k8netd_svc::dns::{DnsForwarder, UpstreamSender};
use k8netd_svc::passt::{self, PasstConfig, PasstProc};
use k8netd_vhost::port::{PortMessage, PortSink, VhostPort};
use serde_json::{Value, json};

/// Default inclusive host-port range for the PublishPort allocator
/// (REQ-010); mirrors the config default.
const DEFAULT_PUBLISH_RANGE: (u16, u16) = (20_000, 21_000);

/// How often each port pump supervises its passt slot: exit detection and
/// crash-restart attempts run at this granularity when the port is idle.
const PASST_SUPERVISE_TICK: Duration = Duration::from_millis(50);

/// SIGTERM grace before SIGKILL when replacing or stopping a passt process.
const PASST_STOP_GRACE: Duration = Duration::from_millis(500);

/// First crash-restart delay; doubles per consecutive failure up to
/// [`PASST_BACKOFF_CAP`] so a broken binary cannot spin the daemon.
const PASST_BACKOFF_BASE: Duration = Duration::from_millis(100);

/// Upper bound for the crash-restart backoff.
const PASST_BACKOFF_CAP: Duration = Duration::from_secs(2);

/// Cap on buffered passt ingress bytes between complete vnet frames;
/// beyond it the accumulator is discarded as corrupt.
const MAX_PASST_PENDING: usize = 1024 * 1024;

/// Ethernet ethertype: ARP (RFC 826).
const ETHERTYPE_ARP: u16 = 0x0806;
/// Ethernet ethertype: IPv4.
const ETHERTYPE_IPV4: u16 = 0x0800;
/// IPv4 protocol number: ICMP.
const IPPROTO_ICMP: u8 = 1;
/// IPv4 protocol number: UDP.
const IPPROTO_UDP: u8 = 17;
/// ICMP message type: echo request.
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP message type: echo reply.
const ICMP_ECHO_REPLY: u8 = 0;
/// DHCPv4 server port.
const DHCP_SERVER_PORT: u16 = 67;
/// DHCPv4 client port.
const DHCP_CLIENT_PORT: u16 = 68;
/// DNS port.
const DNS_PORT: u16 = 53;

/// A live port: control state plus the injection end for its virtqueue.
/// The delivery end is owned exclusively by the port's pump thread.
#[allow(dead_code)] // constructed via ControlPlane impl (bin crate)
struct LivePort {
    /// Numeric switch id assigned at CreatePort (creation order). Names
    /// without digits ("vm-a") cannot derive one, so it is stored here.
    id: u32,
    network: Option<String>,
    mac: Option<MacAddr>,
    /// Handle onto the vhost port; used to pin the NIC MAC at AttachPort
    /// time, before any frontend negotiates the device config space.
    vhost: Arc<VhostPort>,
    /// Switch -> port: ToVm frames destined for this VM.
    inject: Sender<PortMessage>,
}

/// The per-port passt WAN subprocess slot (spec REQ-008/REQ-010).
///
/// `desired` is the configuration the daemon wants running (VM IP plus the
/// port's published forwards); `live` is the current process, absent while
/// crashed and waiting out the restart backoff. PublishPort compares
/// `desired` against the live configuration to keep re-publishes idempotent
/// and restarts passt exactly when the forward set changes.
struct PasstSlot {
    desired: PasstConfig,
    live: Option<PasstProc>,
    /// Consecutive unexpected exits; drives the bounded restart backoff.
    failures: u32,
    /// Earliest permitted next spawn, when backing off.
    next_retry: Option<Instant>,
    /// The WAN uplink's Ethernet MAC, learned from the source of the first
    /// frame passt delivers to the VM (REQ-008). Frames the VM sends back to
    /// this MAC are routed to passt so it can resolve the VM's address and
    /// complete inbound forwards.
    mac: Option<[u8; 6]>,
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
    /// Next numeric switch id to hand out at CreatePort (creation order).
    next_port_id: u32,
    switch: Switch,
    /// Per-network gateway function: ARP responder + WAN egress classifier.
    gateway: Gateway,
    /// Per-port passt slots keyed by port name (REQ-008).
    passts: BTreeMap<String, PasstSlot>,
    /// DNS upstreams for the gateway forwarder (REQ-006); empty until
    /// configured, which answers every query with SERVFAIL.
    dns: RwLock<DnsForwarder>,
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
    /// DNS starts with no upstreams — wire config defaults through
    /// [`set_dns_upstreams`](Self::set_dns_upstreams) before serving.
    /// Test-friendly constructor for empty or pre-existing publish state.
    pub fn new(socket_dir: impl Into<PathBuf>) -> Self {
        let socket_dir = socket_dir.into();
        let publish_table = k8netd_core::state::load_from_disk(&socket_dir)
            .map(|store| store.publish_table)
            .unwrap_or_default();
        Self::from_parts(socket_dir, publish_table)
    }

    /// Creates a dataplane and fails closed when persisted state is corrupt or
    /// incompatible. The compatibility constructor below remains for focused
    /// unit tests that use isolated empty temporary directories.
    pub fn try_new(socket_dir: impl Into<PathBuf>) -> Result<Self, String> {
        let socket_dir = socket_dir.into();
        let publish_table = k8netd_core::state::load_from_disk(&socket_dir)
            .map_err(|error| format!("load persisted k8netd state: {error}"))?
            .publish_table;
        Ok(Self::from_parts(socket_dir, publish_table))
    }

    fn from_parts(socket_dir: PathBuf, publish_table: PublishTable) -> Self {
        Dataplane {
            socket_dir,
            inner: Arc::new(Mutex::new(Inner {
                networks: BTreeMap::new(),
                ports: BTreeMap::new(),
                names: BTreeMap::new(),
                next_port_id: 1,
                switch: Switch::new(),
                gateway: Gateway::new(),
                passts: BTreeMap::new(),
                dns: RwLock::new(DnsForwarder::new(Vec::new())),
                publish_range: DEFAULT_PUBLISH_RANGE,
                publish_table,
            })),
        }
    }

    /// Replaces the DNS upstreams used by the gateway forwarder (REQ-006).
    ///
    /// The daemon wires the configured default resolvers here at startup;
    /// tests may inject stub senders. Safe to call again at any time.
    pub fn set_dns_upstreams(&mut self, upstreams: Vec<Box<dyn UpstreamSender>>) {
        let g = lock(&self.inner).expect("dataplane mutex poisoned");
        let count = upstreams.len();
        *g.dns.write().unwrap_or_else(|p| p.into_inner()) = DnsForwarder::new(upstreams);
        tracing::info!(upstreams = count, "dns upstreams configured");
    }

    /// Persists the complete network, port, IPAM, and publish state.
    fn persist(&self, inner: &Inner) -> Result<(), RpcError> {
        let mut store = StateStore {
            publish_table: inner.publish_table.clone(),
            ..StateStore::default()
        };
        for (name, entry) in &inner.networks {
            let network = entry.ipam.network();
            store.networks.insert(
                name.clone(),
                NetworkState {
                    cidr: network.cidr.to_string(),
                    gateway: network.gateway.to_string(),
                    dns: Vec::new(),
                    mtu: 1500,
                    params: entry.created_with.clone(),
                    pool_start: Some(network.pool.start.to_string()),
                    pool_end: Some(network.pool.end.to_string()),
                },
            );
            store.ipam_records.extend(entry.ipam.snapshot());
        }
        for (name, port) in &inner.ports {
            store.ports.insert(
                name.clone(),
                PortState {
                    vm_ip: port
                        .mac
                        .and_then(|mac| {
                            port.network
                                .as_ref()
                                .and_then(|network| inner.networks.get(network)?.ipam.lookup(mac))
                        })
                        .map(|ip| ip.to_string()),
                    mac: port.mac.map(|mac| mac.to_string()),
                    ipam: IpamSnapshot {
                        free_ranges: Vec::new(),
                        allocations: BTreeMap::new(),
                    },
                },
            );
        }
        k8netd_core::state::save_to_disk(&store, &self.socket_dir).map_err(|_| RpcError::Internal)
    }

    /// Spawns the per-port pump: FromVm frames run the service seam (DHCP /
    /// DNS), then the gateway seam (ARP / WAN egress), then the L2 switch;
    /// between frames the pump supervises the port's passt slot.
    fn spawn_pump(name: String, me: PortId, deliver: Receiver<PortMessage>, inner: Arc<Mutex<Inner>>) {
        thread::spawn(move || {
            let mut last_check = Instant::now();
            loop {
                match deliver.recv_timeout(PASST_SUPERVISE_TICK) {
                    Ok(PortMessage::FromVm(frame)) => pump_frame(&name, me, &frame, &inner),
                    Ok(_) => {}
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
                if last_check.elapsed() >= PASST_SUPERVISE_TICK {
                    last_check = Instant::now();
                    if let Ok(mut g) = inner.lock() {
                        supervise_passt(&mut g, &name);
                    }
                }
            }
        });
    }

    /// Spawns the per-port passt ingress reader: adopts whichever passt
    /// stream the slot currently holds, decodes vnet-framed frames, and
    /// injects them into the owning port's virtqueue. Exits when the port
    /// is deleted; parks while the port has no live passt.
    fn spawn_passt_reader(name: String, inner: Arc<Mutex<Inner>>, inject: Sender<PortMessage>, vhost: Arc<VhostPort>) {
        thread::spawn(move || {
            loop {
                let adopted = {
                    let Ok(g) = inner.lock() else {
                        thread::sleep(PASST_SUPERVISE_TICK);
                        continue;
                    };
                    match g.passts.get(&name).and_then(|slot| slot.live.as_ref()) {
                        Some(p) => p.stream.try_clone(),
                        None => {
                            if !g.ports.contains_key(&name) {
                                return; // owning port deleted: reader retires
                            }
                            drop(g);
                            thread::sleep(PASST_SUPERVISE_TICK);
                            continue;
                        }
                    }
                };
                match adopted {
                    Ok(mut stream) => read_passt_frames(&name, &mut stream, &inject, &vhost, Arc::clone(&inner)),
                    Err(_) => thread::sleep(PASST_SUPERVISE_TICK),
                }
                // EOF or error: the manager replaced or stopped this passt.
                // Yield briefly so it can finish swapping the slot before this
                // reader adopts the next stream.
                thread::sleep(Duration::from_millis(20));
            }
        });
    }
}

/// Ports are numbered by creation order inside the switch; the id is
/// assigned at CreatePort and stored on the LivePort entry.
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
        // The gateway function mirrors every network so ARP/WAN
        // classification uses live configuration (REQ-007).
        g.gateway.add_network(&network);
        let ipam = Ipam::new(network);
        g.networks.insert(
            name,
            NetworkEntry {
                ipam,
                created_with: params.clone(),
            },
        );
        self.persist(&g)?;
        Ok(Value::Null)
    }

    fn delete_network(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?;
        let mut g = lock(&self.inner)?;
        g.gateway.remove_network(name);
        let removed = g.networks.remove(name).map(|_| Value::Null).ok_or(RpcError::NotFound)?;
        self.persist(&g)?;
        Ok(removed)
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
        let vhost = Arc::new(
            VhostPort::new(
                &sock,
                &name,
                PortSink {
                    tx: deliver_tx,
                    rx: inject_rx,
                },
            )
            .map_err(|_| RpcError::Internal)?,
        );
        // The pump owns the delivery end exclusively; the passt ingress
        // reader shares the injection end (REQ-008 wiring).
        let id = g.next_port_id;
        g.next_port_id += 1;
        Dataplane::spawn_pump(name.clone(), PortId(id), deliver_rx, Arc::clone(&self.inner));
        g.switch.add_port(PortId(id), "");
        g.names.insert(id, name.clone());
        g.ports.insert(
            name.clone(),
            LivePort {
                id,
                network: None,
                mac: None,
                vhost: Arc::clone(&vhost),
                inject: _inject_tx_for_test.clone(),
            },
        );
        Dataplane::spawn_passt_reader(name, Arc::clone(&self.inner), _inject_tx_for_test, vhost);
        self.persist(&g)?;
        Ok(Value::Null)
    }

    fn delete_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?;
        let mut g = lock(&self.inner)?;
        match g.ports.remove(name) {
            Some(lp) => {
                let num = lp.id;
                if let (Some(network), Some(mac)) = (lp.network, lp.mac)
                    && let Some(entry) = g.networks.get_mut(&network)
                {
                    // Delete owns the final lifecycle cleanup; stale/missing
                    // allocations are already absent and need no retry error.
                    let _ = entry.ipam.release(mac);
                }
                g.switch.remove_port(PortId(num));
                g.gateway.remove_port(PortId(num));
                g.names.remove(&num);
                // REQ-010: deleting the owning port frees its allocations.
                g.publish_table.remove_port(name);
                self.persist(&g)?;
                // REQ-008: the port's passt is stopped and forgotten with it.
                teardown_passt(&mut g, name);
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
        {
            let port = g.ports.get(&port_name).ok_or(RpcError::NotFound)?;
            if port.network.as_deref() == Some(net_name.as_str()) && port.mac == Some(mac) {
                return Ok(Value::Null); // idempotent re-attach
            }
            if port.network.is_some() {
                return Err(RpcError::Conflict);
            }
        }
        {
            let network = g.networks.get_mut(&net_name).ok_or(RpcError::NotFound)?;
            // Reserve only after attachment compatibility is established so a
            // conflicting request cannot leak an IPAM allocation.
            network.ipam.allocate(mac).map_err(ipam_err)?;
        }
        let port = g.ports.get_mut(&port_name).expect("checked above");
        // Pin the NIC MAC into the device config space so the guest driver
        // probes with exactly the address reserved here (REQ-004/REQ-009).
        port.vhost.set_mac(mac.octets());
        let id = port.id;
        port.network = Some(net_name.clone());
        port.mac = Some(mac);
        g.switch.add_port(PortId(id), &net_name);
        g.gateway.add_port(PortId(id), &net_name);

        // REQ-008: every attached VM gets a WAN passt — even with no
        // published forwards — so out-of-CIDR IPv4 egress works for VMs that
        // never call PublishPort (e.g. worker nodes). The VM IP is the
        // attach-time IPAM reservation for this MAC; an empty forward set
        // renders `passt -a <vm-ip>` with no `-t` flags, which still provides
        // outbound NAT. PublishPort later upgrades this same slot with its
        // forwards (ensure_passt restarts passt when the forward set changes).
        let vm_ip = g.networks[&net_name].ipam.lookup(mac).ok_or(RpcError::NotFound)?;
        ensure_passt(&mut g, &port_name, &vm_ip.to_string(), BTreeMap::new())?;
        self.persist(&g)?;

        Ok(Value::Null)
    }

    fn detach_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_p(params, "name")?;
        let mut g = lock(&self.inner)?;
        let (id, network, mac) = {
            let p = g.ports.get_mut(name).ok_or(RpcError::NotFound)?;
            // Socket stays alive across detach (REQ-003); leave the L2 segment.
            (p.id, p.network.take(), p.mac.take())
        };
        g.gateway.remove_port(PortId(id));
        g.switch.remove_port(PortId(id));
        if let (Some(network), Some(mac)) = (network, mac) {
            let entry = g.networks.get_mut(&network).ok_or(RpcError::NotFound)?;
            entry.ipam.release(mac).map_err(ipam_err)?;
        }
        // REQ-010: detaching the owning port frees its published allocations.
        g.publish_table.remove_port(name);
        self.persist(&g)?;
        // REQ-008: the port left the segment; its WAN identity is gone.
        teardown_passt(&mut g, name);
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
        self.persist(&g)?;
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
        tracing::info!(port = port_name, vm_port, host_port, "published port forward");

        // REQ-008/REQ-010: PublishPort ensures the per-port passt reflects
        // the full published forward set — spawn on first publish, restart
        // with both flags when the set changes, no-op when unchanged.
        let port = g.ports.get(port_name).ok_or(RpcError::NotFound)?;
        let net_name = port.network.clone().ok_or(RpcError::NotFound)?;
        let mac = port.mac.ok_or(RpcError::Internal)?;
        let net = g.networks.get(&net_name).ok_or(RpcError::NotFound)?;
        // The VM IP is the attach-time IPAM reservation for the port's MAC.
        let vm_ip = net.ipam.lookup(mac).ok_or(RpcError::NotFound)?;
        let published = g.publish_table.entries.get(port_name).cloned().unwrap_or_default();
        ensure_passt(&mut g, port_name, &vm_ip.to_string(), published)?;

        Ok(json!({ "host_port": host_port }))
    }

    fn unpublish_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let port_name = str_p(params, "port")?;
        let vm_port = u16_p(params, "vm_port")?;
        let mut g = lock(&self.inner)?;
        g.publish_table.remove(port_name, vm_port).ok_or(RpcError::NotFound)?;
        self.persist(&g)?;
        let published = g.publish_table.entries.get(port_name).cloned().unwrap_or_default();
        if published.is_empty() {
            teardown_passt(&mut g, port_name);
        } else {
            let port = g.ports.get(port_name).ok_or(RpcError::NotFound)?;
            let net_name = port.network.clone().ok_or(RpcError::NotFound)?;
            let mac = port.mac.ok_or(RpcError::Internal)?;
            let vm_ip = g
                .networks
                .get(&net_name)
                .ok_or(RpcError::NotFound)?
                .ipam
                .lookup(mac)
                .ok_or(RpcError::NotFound)?;
            ensure_passt(&mut g, port_name, &vm_ip.to_string(), published)?;
        }
        tracing::info!(port = port_name, vm_port, "unpublished port forward");
        Ok(Value::Null)
    }
}

// -- wiring seams (TASK-004) ------------------------------------------------

/// Processes one VM-emitted frame on the port's pump thread.
///
/// Order matters (REQ-005/006/007): DHCP and DNS-to-gateway are answered by
/// the daemon BEFORE classification — a bare gateway wiring would send
/// 255.255.255.255 to passt (outside CIDR) and drop gateway-IP traffic as
/// in-CIDR L2. Then the gateway classifies ARP / WAN egress; everything else
/// keeps the switch fabric semantics unchanged.
fn pump_frame(name: &str, me: PortId, frame: &[u8], inner: &Arc<Mutex<Inner>>) {
    tracing::trace!(port = name, len = frame.len(), prefix = %hex_prefix(frame), "pump frame in");
    let Ok(mut g) = inner.lock() else { return };
    if let Some(reply) = service_reply(&g, name, frame) {
        tracing::trace!(port = name, reply_len = reply.len(), "pump: service seam answered");
        inject_to(&g, name, reply);
        return;
    }
    // ARP is answered by the core gateway function (REQ-007); every other
    // ARP frame stays on the L2 fabric.
    if ethertype(frame) == Some(ETHERTYPE_ARP)
        && let GatewayAction::ArpReply(reply) = g.gateway.handle_frame(me, frame)
    {
        tracing::debug!(port = name, "answered ARP for the gateway IP");
        inject_to(&g, name, reply);
        return;
    }
    // ICMP echo requests addressed to the gateway IP are answered locally so
    // hosts can probe reachability of their router (gateway presence,
    // REQ-007); every other frame keeps the fabric semantics.
    if ethertype(frame) == Some(ETHERTYPE_IPV4)
        && let Some(reply) = gateway_icmp_reply(&g, name, frame)
    {
        tracing::trace!(port = name, "answered ICMP echo for the gateway IP");
        inject_to(&g, name, reply);
        return;
    }
    // IPv4 egress (REQ-007): a frame addressed to the ingress network's
    // gateway MAC (the VM's default router) goes to this port's own passt;
    // every other destination — including pod-CIDR traffic the VM routes to
    // a peer VM's MAC — stays on the switch fabric unchanged. Classified via
    // the gateway core so the destination MAC is read with the same tolerant
    // header handling the ARP seam uses.
    if ethertype(frame) == Some(ETHERTYPE_IPV4)
        && let GatewayAction::Wan(wan) = g.gateway.handle_frame(me, frame)
    {
        passt_egress(&mut g, name, wan);
        return;
    }
    // WAN uplink replies (REQ-008): a frame the VM sends back to the passt
    // MAC it learned from passt's own frames (e.g. an ARP reply to passt's
    // who-has) must reach passt, not just the L2 fabric — passt is not a
    // switch port, so the fabric would flood it to the other VMs and drop it.
    if let Some(passt_mac) = g.passts.get(name).and_then(|slot| slot.mac)
        && frame.len() >= 6
        && frame[..6] == passt_mac
    {
        tracing::trace!(port = name, "routing frame to passt (WAN uplink MAC)");
        passt_egress(&mut g, name, frame);
        return;
    }
    let targets: Vec<(String, Vec<u8>)> = g
        .switch
        .forward(me, frame)
        .into_iter()
        .filter(|(pid, _)| pid.0 != me.0)
        // Resolve the numeric switch id back to the port name.
        .filter_map(|(pid, f)| g.names.get(&pid.0).map(|n| (n.clone(), f.to_vec())))
        .collect();
    tracing::trace!(port = name, targets = targets.len(), "pump: switch fabric outcome");
    for (peer, f) in targets {
        inject_to(&g, &peer, f);
    }
}

/// First 16 bytes of `frame` as lowercase hex (trace diagnostics).
fn hex_prefix(frame: &[u8]) -> String {
    frame.iter().take(48).map(|b| format!("{b:02x}")).collect()
}

/// Answers the daemon-hosted services for one ingress frame: DHCP on UDP
/// 68->67 from the network's live IPAM reservations (REQ-005), DNS to the
/// gateway IP through the configured upstreams (REQ-006). Returns the full
/// reply Ethernet frame to inject back into the requesting port, or None
/// when the frame is not a service request or got no answer.
fn service_reply(g: &Inner, port: &str, frame: &[u8]) -> Option<Vec<u8>> {
    let lp = g.ports.get(port)?;
    let net_name = lp.network.as_deref()?;
    let entry = g.networks.get(net_name)?;
    let gateway_ip = entry.ipam.network().gateway;
    let vm_mac = lp.mac?;
    let ip = parse_ipv4(frame)?;
    if ip.proto != IPPROTO_UDP || ip.payload.len() < 8 {
        return None;
    }
    let sport = u16::from_be_bytes([ip.payload[0], ip.payload[1]]);
    let dport = u16::from_be_bytes([ip.payload[2], ip.payload[3]]);
    let ulen = usize::from(u16::from_be_bytes([ip.payload[4], ip.payload[5]])).max(8);
    let udp_payload = &ip.payload[8..ulen.min(ip.payload.len())];

    if dport == DHCP_SERVER_PORT && sport == DHCP_CLIENT_PORT {
        // A fresh server per exchange: its IPAM snapshot always reflects
        // the reservations live at this moment (attach-time included).
        let mut server = DhcpServer::new(entry.ipam.clone());
        let reply = server.handle(udp_payload)?.to_vec();
        let yiaddr = reply
            .get(16..20)
            .map(|o| Ipv4Addr::new(o[0], o[1], o[2], o[3]))
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        // TASK-005: DHCP replies are Ethernet-addressed to the sender MAC
        // parsed from the request's Ethernet source (the guest's actual
        // NIC), not the port's pinned MAC; a NAK (yiaddr unspecified) is
        // broadcast by the wrapper. The Ethernet source is always present
        // here (a DHCP request that reached the handler is >= 14+20+8+240
        // bytes); the fallback keeps the old addressing for runts.
        let sender_mac = frame
            .get(6..12)
            .and_then(|m| <[u8; 6]>::try_from(m).ok())
            .unwrap_or_else(|| vm_mac.octets());
        tracing::info!(port, mac = %hex_prefix(&sender_mac), yiaddr = %yiaddr, "dhcp lease served");
        return Some(wrap_udp_reply(
            &reply,
            MacAddr::from_bytes(sender_mac),
            gateway_ip,
            yiaddr,
            DHCP_SERVER_PORT,
            DHCP_CLIENT_PORT,
        ));
    }

    if dport == DNS_PORT && ip.dst == gateway_ip {
        let answer = {
            let forwarder = g.dns.read().unwrap_or_else(|p| p.into_inner());
            forwarder.handle(udp_payload)?
        };
        tracing::info!(port, bytes = answer.len(), "dns query relayed via gateway");
        return Some(wrap_udp_reply(&answer, vm_mac, gateway_ip, ip.src, DNS_PORT, sport));
    }
    None
}

/// Writes one WAN-bound frame vnet-framed to the port's own passt fd
/// (REQ-007 egress). Dropped when the port has no live passt.
fn passt_egress(g: &mut Inner, port: &str, frame: &[u8]) {
    let Some(slot) = g.passts.get_mut(port) else {
        tracing::trace!(port, "wan egress dropped: no passt slot");
        return;
    };
    let Some(p) = slot.live.as_mut() else {
        tracing::trace!(port, "wan egress dropped: passt not running");
        return;
    };
    let framed = passt::encode_frame(frame);
    match p.stream.write_all(&framed).and_then(|()| p.stream.flush()) {
        Ok(()) => tracing::trace!(port, bytes = framed.len(), "wan frame egressed to passt"),
        Err(e) => tracing::warn!(port, %e, "passt egress write failed"),
    }
}

/// Injects one frame into `port`'s virtqueue and wakes the port's RX
/// worker; false when the port is gone.
fn inject_to(g: &Inner, port: &str, frame: Vec<u8>) -> bool {
    match g.ports.get(port) {
        Some(lp) => {
            let sent = lp.inject.send(PortMessage::ToVm(frame)).is_ok();
            if sent {
                lp.vhost.kick_rx();
            }
            sent
        }
        None => false,
    }
}

/// Decodes the first length-prefixed frame in `buf`, returning
/// `(consumed_len, payload)`.
fn next_frame(buf: &[u8]) -> Option<(usize, Vec<u8>)> {
    let payload = passt::decode_frame(buf).ok()?;
    Some((passt::FRAME_HEADER_LEN + payload.len(), payload.to_vec()))
}

/// Blocking read loop over one adopted passt stream: accumulates bytes,
/// decodes length-prefixed frames, and injects wire->VM payloads into the
/// owning port's virtqueue (REQ-008 ingress), waking the RX worker per
/// frame. Returns at EOF/error — the manager replaced or stopped the
/// process.
fn read_passt_frames(
    name: &str,
    stream: &mut UnixStream,
    inject: &Sender<PortMessage>,
    vhost: &VhostPort,
    inner: Arc<Mutex<Inner>>,
) {
    let mut buf = [0u8; 65_536];
    let mut pending: Vec<u8> = Vec::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                tracing::trace!(port = name, bytes = n, "passt ingress read");
                pending.extend_from_slice(&buf[..n]);
                while let Some((consumed, payload)) = next_frame(&pending) {
                    pending.drain(..consumed);
                    tracing::trace!(port = name, len = payload.len(), prefix = %hex_prefix(&payload), "passt ingress frame");
                    // Learn the WAN uplink's MAC from the source of the
                    // frames it delivers, so the pump can route the VM's
                    // replies (notably ARP) back to passt (REQ-008).
                    if payload.len() >= 6 {
                        let mac: [u8; 6] = payload[6..12].try_into().expect("6-byte slice");
                        if let Ok(mut g) = inner.lock()
                            && let Some(slot) = g.passts.get_mut(name)
                            && slot.mac != Some(mac)
                        {
                            slot.mac = Some(mac);
                            tracing::trace!(port = name, mac = %hex_prefix(&mac), "passt mac learned");
                        }
                    }
                    if inject.send(PortMessage::ToVm(payload)).is_err() {
                        return; // owning port deleted: reader retires
                    }
                    vhost.kick_rx();
                }
                if pending.len() > MAX_PASST_PENDING {
                    tracing::warn!(port = name, "passt ingress buffer overrun; discarding");
                    pending.clear();
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// Ensures the port's passt slot runs `published` forwards against `vm_ip`
/// (REQ-008/REQ-010): no-op when an identical configuration is already
/// live, otherwise terminates the old process and spawns a new one with
/// the pinned argv (`--fd <n> -a <vm_ip>` plus one `-t` per forward).
fn ensure_passt(g: &mut Inner, port: &str, vm_ip: &str, published: BTreeMap<u16, u16>) -> Result<(), RpcError> {
    // Pin the passt subnet view to the owning network: the netmask from the
    // CIDR and the gateway the daemon's ARP responder already answers for.
    // Without these, passt derives its view from the host's default-route
    // interface and a foreign pasta tap can pull the VM IP off-link,
    // silently blackholing every published-port connection.
    let net_name = g
        .ports
        .get(port)
        .and_then(|p| p.network.clone())
        .ok_or(RpcError::NotFound)?;
    let net = g.networks.get(&net_name).ok_or(RpcError::NotFound)?;
    let model = net.ipam.network();
    let netmask = model.cidr.netmask().to_string();
    let gateway = model.gateway.to_string();
    let config = passt::passt_config_for(vm_ip, &netmask, &gateway, &published);
    let slot = g.passts.entry(port.to_string()).or_insert(PasstSlot {
        desired: config.clone(),
        live: None,
        failures: 0,
        next_retry: None,
        mac: None,
    });
    if slot.live.is_some() && slot.desired == config {
        return Ok(()); // idempotent re-publish
    }
    if let Some(mut old) = slot.live.take() {
        tracing::info!(port, pid = old.id(), "restarting passt: published forwards changed");
        let _ = old.stream.shutdown(Shutdown::Both);
        let _ = old.terminate(PASST_STOP_GRACE);
    }
    slot.desired = config.clone();
    match PasstProc::spawn(&config) {
        Ok(p) => {
            tracing::info!(
                port,
                pid = p.id(),
                forwards = config.forwards.len(),
                vm_ip,
                "passt spawned"
            );
            slot.failures = 0;
            slot.next_retry = None;
            slot.live = Some(p);
            Ok(())
        }
        Err(e) => {
            slot.failures = slot.failures.saturating_add(1);
            let delay = restart_backoff(slot.failures);
            slot.next_retry = Some(Instant::now() + delay);
            tracing::warn!(port, %e, backoff_ms = delay.as_millis() as u64, "passt spawn failed");
            Err(RpcError::Internal)
        }
    }
}

/// Stops the port's passt (if any) and forgets the slot: the socket is shut
/// down first so the ingress reader observes EOF immediately, then the child
/// gets SIGTERM with a bounded SIGKILL grace (REQ-008 lifecycle).
fn teardown_passt(g: &mut Inner, port: &str) {
    let Some(slot) = g.passts.remove(port) else { return };
    let Some(mut p) = slot.live else { return };
    let pid = p.id();
    let _ = p.stream.shutdown(Shutdown::Both);
    match p.terminate(PASST_STOP_GRACE) {
        Ok(()) => tracing::info!(port, pid, "passt stopped"),
        Err(e) => tracing::warn!(port, pid, %e, "passt termination failed"),
    }
}

/// Supervises the port's passt slot once per pump tick: detects unexpected
/// exits (scheduling a bounded-backoff retry) and respawns when due. The
/// restart-on-exit policy lives here; the subprocess mechanics stay in the
/// svc crate (REQ-008).
fn supervise_passt(g: &mut Inner, port: &str) {
    let Some(slot) = g.passts.get_mut(port) else { return };

    let crashed = slot.live.as_mut().is_some_and(PasstProc::exited);
    if crashed {
        let pid = slot.live.as_ref().map(PasstProc::id);
        slot.live = None;
        slot.failures = slot.failures.saturating_add(1);
        let delay = restart_backoff(slot.failures);
        slot.next_retry = Some(Instant::now() + delay);
        tracing::warn!(
            port,
            ?pid,
            failures = slot.failures,
            backoff_ms = delay.as_millis() as u64,
            "passt exited unexpectedly; restart scheduled"
        );
    }

    if slot.live.is_none() && slot.next_retry.is_none_or(|due| Instant::now() >= due) {
        match PasstProc::spawn(&slot.desired) {
            Ok(p) => {
                tracing::info!(port, pid = p.id(), "passt restarted");
                slot.failures = 0;
                slot.next_retry = None;
                slot.live = Some(p);
            }
            Err(e) => {
                slot.failures = slot.failures.saturating_add(1);
                let delay = restart_backoff(slot.failures);
                slot.next_retry = Some(Instant::now() + delay);
                tracing::warn!(port, %e, backoff_ms = delay.as_millis() as u64, "passt respawn failed");
            }
        }
    }
}

/// Crash-restart delay for `failures` consecutive exits: 100ms doubling up
/// to a 2s cap so a broken binary cannot spin the daemon.
fn restart_backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    (PASST_BACKOFF_BASE * (1u32 << shift)).min(PASST_BACKOFF_CAP)
}

// -- frame helpers ------------------------------------------------------------

/// An IPv4 packet carried over Ethernet, parsed tolerantly.
struct Ipv4Frame<'a> {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    /// IP protocol number (17 = UDP).
    proto: u8,
    /// Bytes after the IPv4 header (the transport PDU).
    payload: &'a [u8],
}

/// Returns the Ethernet ethertype of `frame`, or None for runts.
fn ethertype(frame: &[u8]) -> Option<u16> {
    if frame.len() < 14 {
        return None;
    }
    Some(u16::from_be_bytes([frame[12], frame[13]]))
}

/// Parses the IPv4 envelope of an Ethernet frame.
///
/// The header length comes from IHL, but the header END is probed: the
/// protocol byte sits either 11 bytes before the payload (RFC 791 layout)
/// or 12 bytes before it (a compact layout missing the TTL byte, emitted by
/// lab fixtures). The standard layout wins whenever it carries a routable
/// protocol number there; frames matching neither are dropped (None), never
/// misread and never a panic.
fn parse_ipv4(frame: &[u8]) -> Option<Ipv4Frame<'_>> {
    if ethertype(frame)? != ETHERTYPE_IPV4 {
        return None;
    }
    let ihl = usize::from(frame[14] & 0x0f) * 4;
    if frame[14] >> 4 != 4 || ihl < 20 {
        return None;
    }
    let is_routable = |b: u8| matches!(b, 1 | 6 | 17 | 47 | 50 | 51 | 58);
    let std_end = 14 + ihl;
    let end = if std_end <= frame.len() && is_routable(frame[std_end - 11]) {
        std_end
    } else if std_end <= frame.len() && is_routable(frame[std_end - 12]) {
        std_end - 1
    } else {
        return None;
    };
    let octets = |o: &[u8]| Ipv4Addr::new(o[0], o[1], o[2], o[3]);
    Some(Ipv4Frame {
        src: octets(frame.get(end - 8..end - 4)?),
        dst: octets(frame.get(end - 4..end)?),
        proto: frame[end - 11],
        payload: &frame[end..],
    })
}

/// Builds the ICMP echo reply for a request addressed to `port`'s network
/// gateway, or None when the frame is not an echo request for the gateway.
/// The IP packet is reflected with swapped addresses; both checksums are
/// recomputed (REQ-007 gateway presence).
fn gateway_icmp_reply(g: &Inner, port: &str, frame: &[u8]) -> Option<Vec<u8>> {
    let lp = g.ports.get(port)?;
    let entry = g.networks.get(lp.network.as_deref()?)?;
    let gateway_ip = entry.ipam.network().gateway;
    let vm_mac = lp.mac?;
    let ip = parse_ipv4(frame)?;
    if ip.dst != gateway_ip || ip.proto != IPPROTO_ICMP {
        return None;
    }
    // Echo request carries at least type, code, checksum, id and seq.
    if ip.payload.first() != Some(&ICMP_ECHO_REQUEST) || ip.payload.len() < 8 {
        return None;
    }

    let mut pkt = frame[14..].to_vec();
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < 20 || ihl > pkt.len() {
        return None;
    }
    // ICMP echo reply: flip the type, zero the checksum field, recompute.
    pkt[ihl] = ICMP_ECHO_REPLY;
    pkt[ihl + 2..ihl + 4].copy_from_slice(&[0, 0]);
    let icmp_sum = inet_checksum(&pkt[ihl..]);
    pkt[ihl + 2..ihl + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    // Swap source and destination addresses, refresh TTL and IP checksum.
    pkt.copy_within(12..16, 16);
    pkt[12..16].copy_from_slice(&gateway_ip.octets());
    pkt[8] = 64;
    pkt[10..12].copy_from_slice(&[0, 0]);
    let ip_sum = inet_checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let mut out = Vec::with_capacity(14 + pkt.len());
    out.extend_from_slice(&vm_mac.octets());
    out.extend_from_slice(&gateway_mac(gateway_ip));
    out.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    out.extend_from_slice(&pkt);
    Some(out)
}

/// Computes the ones-complement Internet checksum over `data`.
fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (words, remainder) = data.as_chunks::<2>();
    for word in words {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    if let [last] = remainder {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Wraps a service reply payload (DHCP packet or DNS message) into a full
/// Ethernet/IPv4/UDP frame from the gateway to the VM: source MAC derived
/// from the gateway IP (REQ-007), IPv4 header checksummed, UDP checksum
/// zero (legal over IPv4). `reply_ip` selects the destination IP: the
/// offered address when present, broadcast otherwise. The Ethernet
/// destination is `vm_mac` — for DHCP the request's sender MAC, for other
/// services the port's pinned MAC — except that an unspecified `reply_ip`
/// (a DHCP NAK) is broadcast at the Ethernet and IP destination layers so
/// a guest whose NIC MAC differs from the pinned MAC still receives it;
/// the IP source stays the gateway (a broadcast source is dropped as a
/// martian by Linux before UDP delivery) (TASK-005).
fn wrap_udp_reply(
    payload: &[u8],
    vm_mac: MacAddr,
    gateway_ip: Ipv4Addr,
    reply_ip: Ipv4Addr,
    sport: u16,
    dport: u16,
) -> Vec<u8> {
    let dst_ip = if reply_ip.is_unspecified() {
        Ipv4Addr::BROADCAST
    } else {
        reply_ip
    };
    let dst_mac = if reply_ip.is_unspecified() {
        [0xff; 6]
    } else {
        vm_mac.octets()
    };
    let udp_len = 8 + payload.len();
    let mut out = Vec::with_capacity(14 + 20 + udp_len);
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&gateway_mac(gateway_ip));
    out.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    let mut iph = [0u8; 20];
    iph[0] = 0x45; // version 4, IHL 5
    iph[2..4].copy_from_slice(&(u16::try_from(20 + udp_len).unwrap_or(u16::MAX)).to_be_bytes());
    iph[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    iph[8] = 64; // TTL
    iph[9] = IPPROTO_UDP;
    iph[12..16].copy_from_slice(&gateway_ip.octets());
    iph[16..20].copy_from_slice(&dst_ip.octets());
    let cksum = ipv4_checksum(&iph);
    iph[10..12].copy_from_slice(&cksum.to_be_bytes());
    out.extend_from_slice(&iph);

    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    out.extend_from_slice(&(u16::try_from(udp_len).unwrap_or(u16::MAX)).to_be_bytes());
    out.extend_from_slice(&[0, 0]); // UDP checksum: 0 is legal over IPv4
    out.extend_from_slice(payload);
    out
}

/// Derives the gateway MAC from the gateway IP: 02:00:<o1>:<o2>:<o3>:<o4>
/// (the same derivation the core gateway function pins, REQ-007).
fn gateway_mac(gateway: Ipv4Addr) -> [u8; 6] {
    let o = gateway.octets();
    [0x02, 0x00, o[0], o[1], o[2], o[3]]
}

/// Computes the ones-complement IPv4 header checksum over `header`.
fn ipv4_checksum(header: &[u8; 20]) -> u16 {
    let mut sum = 0u32;
    for word in header.as_chunks::<2>().0 {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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
    use k8netd_vhost::port::{RX_VRING, TX_VRING, VNET_HDR_LEN, decode_driver_rx, encode_driver_tx};

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
        // TEMP DEBUG
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("trace"))
            .try_init();
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

        // VM-A emits a broadcast frame on its TX vring (vnet-headered).
        let frame = vec![0xffu8; 60];
        let wire = encode_driver_tx(&frame);
        let tx_addr = GUEST_BASE + DATA_OFFSET;
        vm_memory::Bytes::write_slice(fe1.mem(), &wire, vm_memory::GuestAddress(tx_addr))?;
        post_desc_and_kick(
            fe1.mem(),
            fe1.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            wire.len() as u32,
            0,
        )?;

        // VM-B must receive it in a used writable buffer on its RX vring,
        // behind the vnet header the driver expects.
        let got = wait_frame(fe2.mem(), rx_addr, Duration::from_secs(5))?;
        assert_eq!(
            decode_driver_rx(&got)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on delivered frame")?,
            frame,
            "broadcast must arrive intact at the peer"
        );

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
    // -----------------------------------------------------------------------
    // TASK-004 (data-plane wiring, red phase). Pins the four seams flagged by
    // the live diagnosis (2026-08-26): PublishPort must ensure the per-port
    // passt process (REQ-008/REQ-010 argv contract), DeletePort/DetachPort
    // must stop it, an exited passt must be re-ensured, and the pump must
    // hook the gateway (WAN egress + passt ingress) and the DHCP/DNS
    // services (REQ-005/REQ-006/REQ-007). Red modes:
    //   - most tests are runtime-red today (publish_port only records the
    //     allocation; nothing spawns passt; the pump has no gateway/DHCP
    //     hooks); they compile against existing public API only;
    //   - the DNS test is compile-red: it pins the
    //     `Dataplane::set_dns_upstreams` seam needed to inject a stub
    //     upstream (repo precedent: TASK-014/016 pinned seams via
    //     compile failure).
    // The passt stub follows the k8netd-svc pattern: a shell script named
    // `passt` prepended to PATH that records its pid + argv and, for the
    // fd-serving flavors, exercises the socketpair end passed via `--fd`.
    // -----------------------------------------------------------------------

    /// Serializes tests that swap the process-global PATH (env is not
    /// thread-local; sibling spawns would race the stub).
    static PASST_PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static PASST_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    /// Fresh per-test root under the temp dir (state.json must not leak
    /// between tests through Dataplane::new's restore path).
    fn passt_temp_root(tag: &str) -> std::path::PathBuf {
        let n = PASST_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!("k8netd-dpw-{tag}-{}-{n}", std::process::id()))
    }

    /// Restores PATH on drop so parallel tests do not leak the stub.
    struct PasstPathGuard {
        old: String,
    }

    impl Drop for PasstPathGuard {
        fn drop(&mut self) {
            // SAFETY: restoring the value captured at stub-install time.
            unsafe { std::env::set_var("PATH", &self.old) };
        }
    }

    /// Installs a stub `passt` executable on PATH. Flavors:
    /// - "plain":   record pid+argv, then sleep (stable live passt)
    /// - "crash":   record, exit while `<root>/crash-now` exists, else sleep
    ///              (drives the daemon re-ensure path)
    /// - "capture": record, then `cat` the served fd into egress.bin until
    ///              EOF (captures daemon -> passt egress frames)
    /// - "pipe":    record, wait for `<root>/inbound-cue`, write one
    ///              length-prefixed ingress frame into the served fd, then
    ///              `cat` egress until EOF (drives both gateway directions)
    ///
    /// Every flavor parses the served fd number from the pinned `--fd <n>`
    /// argv pair and appends one line per invocation to `<root>/pids.log`
    /// and `<root>/argv.log` (space-joined arguments).
    fn install_passt_stub(
        root: &std::path::Path,
        flavor: &str,
    ) -> Result<PasstPathGuard, Box<dyn std::error::Error + Send + Sync>> {
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin)?;
        let mut s = format!("#!/bin/bash\nROOT=\"{}\"\n", root.display());
        s.push_str(
            r#"LOG="$ROOT/pids.log"
ARGV="$ROOT/argv.log"
FD=
prev=
for a in "$@"; do
  if [ "$prev" = "--fd" ]; then FD="$a"; fi
  prev="$a"
done
echo $$ >> "$LOG"
printf '%s\n' "$*" >> "$ARGV"
"#,
        );
        match flavor {
            "plain" => s.push_str("exec sleep 30\n"),
            "crash" => s.push_str(
                r#"if [ -f "$ROOT/crash-now" ]; then
  sleep 0.05
  exit 0
fi
exec sleep 30
"#,
            ),
            "capture" => s.push_str(
                r#"if [ -z "$FD" ]; then
  exec sleep 30
fi
cat <&$FD > "$ROOT/egress.bin"
"#,
            ),
            "pipe" => s.push_str(concat!(
                r#"if [ -z "$FD" ]; then
  exec sleep 30
fi
i=0
while [ ! -f "$ROOT/inbound-cue" ] && [ "$i" -lt 400 ]; do
  sleep 0.01
  i=$((i+1))
done
"#,
                // passt -F ingress framing: be32 length (46) + ethernet
                // header dst 02:00:00:00:00:01 src 02:00:c0:a8:7c:01 type
                // 0x0800, then 32 'A' bytes: the frame the test expects.
                r#"printf '\000\000\000\056\002\000\000\000\000\001\002\000\300\250\174\001\010\000' >&$FD
head -c 32 /dev/zero | tr '\000' 'A' >&$FD
cat <&$FD > "$ROOT/egress.bin"
"#,
            )),
            other => panic!("unknown stub flavor {other}"),
        }
        let script = bin.join("passt");
        std::fs::write(&script, s)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))?;
        let old = std::env::var("PATH").unwrap_or_default();
        // SAFETY: caller holds PASST_PATH_LOCK; PATH restored on drop.
        unsafe { std::env::set_var("PATH", format!("{}:{}", bin.display(), old)) };
        Ok(PasstPathGuard { old })
    }

    /// kill(pid, 0) probe: true while the process exists.
    fn pid_alive(pid: u32) -> bool {
        // SAFETY: signal-0 liveness probe; no signal is delivered.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    fn read_lines(path: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .map(|s| s.lines().map(str::to_string).collect())
            .unwrap_or_default()
    }

    fn passt_pids(root: &std::path::Path) -> Vec<u32> {
        read_lines(&root.join("pids.log"))
            .into_iter()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    fn argv_lines(root: &std::path::Path) -> Vec<String> {
        read_lines(&root.join("argv.log"))
    }

    /// Polls `cond` until true or `timeout` elapses.
    fn poll_until(mut cond: impl FnMut() -> bool, timeout: Duration, _what: &str) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if cond() {
                return true;
            }
            if std::time::Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Dataplane with net0 + one attached port; returns the reserved IP.
    fn attached_dp(
        dir: &std::path::Path,
        port: &str,
        mac: &str,
    ) -> Result<(Dataplane, String), Box<dyn std::error::Error + Send + Sync>> {
        let mut dp = Dataplane::new(dir);
        dp.create_network(&net_params())
            .map_err(|e| format!("create_network: {e:?}"))?;
        dp.create_port(&serde_json::json!({ "name": port }))
            .map_err(|e| format!("create_port: {e:?}"))?;
        dp.attach_port(&serde_json::json!({"port": port, "network": "net0", "mac": mac}))
            .map_err(|e| format!("attach_port: {e:?}"))?;
        let ip = dp
            .allocate_ip(&serde_json::json!({"network": "net0", "mac": mac}))
            .map_err(|e| format!("allocate_ip: {e:?}"))?;
        Ok((dp, ip.as_str().expect("bare ip string").to_string()))
    }

    fn publish(dp: &mut Dataplane, port: &str, vm_port: u16) -> u16 {
        let r = dp
            .publish_port(&serde_json::json!({"port": port, "vm_port": vm_port}))
            .expect("publish_port must succeed for an attached port");
        r["host_port"].as_u64().expect("host_port field") as u16
    }

    /// Waits until the passt stub logged at least `n` invocations.
    fn wait_invocations(root: &std::path::Path, n: usize) -> bool {
        poll_until(
            || argv_lines(root).len() >= n && passt_pids(root).len() >= n,
            Duration::from_secs(5),
            "passt invocation",
        )
    }

    /// Waits for the RX used ring to publish element `elem`, returns its len.
    fn wait_used_elem_len(
        mem: &vm_memory::GuestMemoryMmap<()>,
        elem: u16,
        timeout: Duration,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        use vm_memory::{Bytes, GuestAddress};
        let base = vring_base(RX_VRING) + USED_RING_OFFSET;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let idx: u16 = mem.read_obj(GuestAddress(base + 2))?;
            if idx > elem {
                let len: u32 = mem.read_obj(GuestAddress(base + 8 + u64::from(elem) * 8))?;
                return Ok(len);
            }
            if std::time::Instant::now() > deadline {
                panic!("RX used element {elem} never completed");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // -- frame builders (hand-rolled; no new dev-dependencies) --------------

    const DP_GW_MAC: [u8; 6] = [0x02, 0x00, 0xc0, 0xa8, 0x7c, 0x01]; // derived per REQ-007
    const DP_VM_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x09];
    const DP_PEER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
    const DP_GW_IP_OCTETS: [u8; 4] = [192, 168, 124, 1];

    fn eth_frame(dst: &[u8; 6], src: &[u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(14 + payload.len());
        f.extend_from_slice(dst);
        f.extend_from_slice(src);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn ipv4_header(src: [u8; 4], dst: [u8; 4], total_len: u16, proto: u8) -> Vec<u8> {
        let mut h = vec![0x45, 0x00];
        h.extend_from_slice(&total_len.to_be_bytes()); // 2..4 total length
        h.extend_from_slice(&[0, 0]); // 4..6 identification
        h.extend_from_slice(&[0x40, 0]); // 6..8 flags (DF) + fragment offset
        h.push(64); // 8 ttl
        h.push(proto); // 9 protocol
        h.extend_from_slice(&[0, 0]); // 10..12 checksum (caller fixes)
        h.extend_from_slice(&src); // 12..16 source
        h.extend_from_slice(&dst); // 16..20 destination
        h
    }

    fn udp_header(sport: u16, dport: u16, payload_len: usize) -> Vec<u8> {
        let mut h = Vec::with_capacity(8);
        h.extend_from_slice(&sport.to_be_bytes());
        h.extend_from_slice(&dport.to_be_bytes());
        h.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
        h.extend_from_slice(&[0, 0]); // checksum (unchecked here)
        h
    }

    fn ipv4_octets(s: &str) -> [u8; 4] {
        s.split('.')
            .map(|o| o.parse().expect("ipv4 octet"))
            .collect::<Vec<u8>>()
            .try_into()
            .expect("4 octets")
    }

    /// Raw DHCPv4 packet (236-byte header + magic cookie + options).
    fn dhcp_packet(msg_type: u8, xid: u32, mac: &[u8; 6], requested: Option<[u8; 4]>) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1; // BootRequest
        p[1] = 1; // htype ethernet
        p[2] = 6; // hlen
        p[4..8].copy_from_slice(&xid.to_be_bytes());
        p[28..34].copy_from_slice(mac);
        p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
        p.extend_from_slice(&[53u8, 1, msg_type]);
        if let Some(ip) = requested {
            p.extend_from_slice(&[50u8, 4]);
            p.extend_from_slice(&ip);
        }
        p.push(255);
        p
    }

    fn udp_over_eth(
        dst: &[u8; 6],
        src_mac: &[u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        sport: u16,
        dport: u16,
        inner: &[u8],
    ) -> Vec<u8> {
        let udp = udp_header(sport, dport, inner.len());
        let ip = ipv4_header(src_ip, dst_ip, (20 + 8 + inner.len()) as u16, 17);
        let mut payload = ip;
        payload.extend_from_slice(&udp);
        payload.extend_from_slice(inner);
        eth_frame(dst, src_mac, 0x0800, &payload)
    }

    struct DhcpReply {
        msg_type: Option<u8>,
        yiaddr: [u8; 4],
        router: Option<[u8; 4]>,
        dns: Option<[u8; 4]>,
    }

    /// Strips eth+IP+UDP and parses the fields the seam must deliver.
    fn parse_dhcp_reply(frame: &[u8]) -> Option<DhcpReply> {
        if frame.len() < 14 + 20 + 8 + 240 {
            return None;
        }
        let ihl = usize::from(frame[14] & 0x0f) * 4;
        let dhcp = frame.get(14 + ihl + 8..)?;
        if dhcp.len() < 240 || dhcp[236..240] != [0x63, 0x82, 0x53, 0x63] {
            return None;
        }
        let yiaddr = [dhcp[16], dhcp[17], dhcp[18], dhcp[19]];
        let (mut msg_type, mut router, mut dns) = (None, None, None);
        let mut i = 240;
        while i + 2 <= dhcp.len() {
            let code = dhcp[i];
            if code == 0 || code == 255 {
                break;
            }
            let len = dhcp[i + 1] as usize;
            let val = dhcp.get(i + 2..i + 2 + len)?;
            match (code, len) {
                (53, 1) => msg_type = val.first().copied(),
                (3, 4) => router = Some([val[0], val[1], val[2], val[3]]),
                (6, 4) => dns = Some([val[0], val[1], val[2], val[3]]),
                _ => {}
            }
            i += 2 + len;
        }
        Some(DhcpReply {
            msg_type,
            yiaddr,
            router,
            dns,
        })
    }

    /// Minimal A query for example.com.
    fn dns_query_bytes(id: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // RD set
        q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // qdcount=1
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        q
    }

    /// Decodes every complete length-prefixed frame in `buf` (stub-side
    /// capture format).
    fn passt_frames(buf: &[u8]) -> Vec<Vec<u8>> {
        use k8netd_svc::passt::{FRAME_HEADER_LEN, decode_frame};
        let mut out = Vec::new();
        let mut off = 0;
        while off + FRAME_HEADER_LEN <= buf.len() {
            let Ok(payload) = decode_frame(&buf[off..]) else {
                break;
            };
            out.push(payload.to_vec());
            off += FRAME_HEADER_LEN + payload.len();
        }
        out
    }

    // -- requirement 1: publish wiring ---------------------------------------

    /// R1: PublishPort must ensure a passt for the port whose argv carries
    /// `-a <vm_ip>` and `-t<host_port>:<vm_port>` (REQ-008/REQ-010; bare
    /// `hostport:guestport` verified empirically on both passt generations —
    /// Debian trixie 0.0~git20250503 and host 2026_07_28).
    #[test]
    fn publish_port_ensures_passt_with_pinned_argv() -> TestResult {
        // Poisoning-tolerant: a sibling test's red-phase panic must not
        // mask this test's own failure reason.
        let _path_lock = PASST_PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = passt_temp_root("pub-argv");
        std::fs::create_dir_all(&root)?;
        let _guard = install_passt_stub(&root, "plain")?;
        let (mut dp, ip) = attached_dp(&root, "vm1", "02:00:00:00:00:01")?;

        let hp = publish(&mut dp, "vm1", 6443);

        assert!(
            wait_invocations(&root, 1),
            "publish_port must ensure a passt process (none spawned)"
        );
        let want_fwd = format!("-t{hp}:6443");
        let last = argv_lines(&root).last().expect("argv recorded").clone();
        let tokens: Vec<&str> = last.split_whitespace().collect();
        let a_pos = tokens.iter().position(|t| *t == "-a");
        assert_eq!(
            a_pos.and_then(|i| tokens.get(i + 1).copied()),
            Some(ip.as_str()),
            "passt argv must advertise the VM IP via -a; got [{last}]"
        );
        assert!(
            tokens.iter().any(|t| *t == want_fwd),
            "passt argv must contain {want_fwd}; got [{last}]"
        );

        let _ = dp.delete_port(&serde_json::json!({"name": "vm1"}));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    /// R1: an identical re-publish returns the same host port and must NOT
    /// respawn passt (idempotent ensure).
    #[test]
    fn republish_same_pair_does_not_respawn_passt() -> TestResult {
        // Poisoning-tolerant: a sibling test's red-phase panic must not
        // mask this test's own failure reason.
        let _path_lock = PASST_PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = passt_temp_root("pub-idem");
        std::fs::create_dir_all(&root)?;
        let _guard = install_passt_stub(&root, "plain")?;
        let (mut dp, _ip) = attached_dp(&root, "vm1", "02:00:00:00:00:01")?;

        let hp1 = publish(&mut dp, "vm1", 6443);
        assert!(wait_invocations(&root, 1), "first publish must ensure passt");

        // Let any buggy immediate-thrash surface before the re-publish.
        std::thread::sleep(Duration::from_millis(300));
        let count_before = argv_lines(&root).len();

        let hp2 = publish(&mut dp, "vm1", 6443);
        assert_eq!(hp1, hp2, "re-publish must be idempotent");
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(
            argv_lines(&root).len(),
            count_before,
            "identical re-publish must not respawn passt"
        );
        let last = argv_lines(&root).last().expect("argv recorded").clone();
        assert!(last.contains(&format!("-t{hp1}:6443")), "argv unchanged: [{last}]");

        let _ = dp.delete_port(&serde_json::json!({"name": "vm1"}));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    /// REQ-008 (A1): attach_port must spawn an egress passt even for a port
    /// with NO published forwards, so VMs that never call PublishPort (worker
    /// nodes) still get out-of-CIDR egress. The argv carries `-a <vm-ip>` and
    /// no `-t` flags.
    #[test]
    fn attach_port_spawns_egress_passt_without_forwards() -> TestResult {
        let _path_lock = PASST_PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = passt_temp_root("attach-egress");
        std::fs::create_dir_all(&root)?;
        let _guard = install_passt_stub(&root, "plain")?;

        let mut dp = Dataplane::new(&root);
        dp.create_network(&net_params())
            .map_err(|e| format!("create_network: {e:?}"))?;
        dp.create_port(&serde_json::json!({ "name": "vm1" }))
            .map_err(|e| format!("create_port: {e:?}"))?;
        dp.attach_port(&serde_json::json!({"port": "vm1", "network": "net0", "mac": "02:00:00:00:00:01"}))
            .map_err(|e| format!("attach_port: {e:?}"))?;

        assert!(
            wait_invocations(&root, 1),
            "attach_port must ensure a passt process (none spawned)"
        );
        let last = argv_lines(&root).last().expect("argv recorded").clone();
        let tokens: Vec<&str> = last.split_whitespace().collect();
        assert!(
            tokens.iter().any(|t| *t == "-a"),
            "passt argv must advertise the VM IP via -a; got [{last}]"
        );
        assert!(
            !tokens.iter().any(|t| t.starts_with("-t")),
            "attach-only passt must carry no -t forwards; got [{last}]"
        );

        let _ = dp.delete_port(&serde_json::json!({"name": "vm1"}));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    /// R1: publishing a second vm_port on the same port RESTARTS passt and
    /// the new argv carries both -t forwards; the previous process is gone.
    #[test]
    fn publishing_second_vm_port_restarts_passt_with_both_forwards() -> TestResult {
        // Poisoning-tolerant: a sibling test's red-phase panic must not
        // mask this test's own failure reason.
        let _path_lock = PASST_PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = passt_temp_root("pub-restart");
        std::fs::create_dir_all(&root)?;
        let _guard = install_passt_stub(&root, "plain")?;
        let (mut dp, _ip) = attached_dp(&root, "vm1", "02:00:00:00:00:01")?;

        let hp_api = publish(&mut dp, "vm1", 6443);
        assert!(wait_invocations(&root, 1), "first publish must ensure passt");
        std::thread::sleep(Duration::from_millis(200));
        let count_before = argv_lines(&root).len();
        let first_pid = passt_pids(&root).last().copied().expect("first pid");

        let hp_ssh = publish(&mut dp, "vm1", 22);

        assert!(
            wait_invocations(&root, count_before + 1),
            "second vm_port publish must restart passt (invocations: {})",
            argv_lines(&root).len()
        );
        let last = argv_lines(&root).last().expect("argv recorded").clone();
        assert!(
            last.contains(&format!("-t{hp_api}:6443")),
            "restarted argv keeps the first forward: [{last}]"
        );
        assert!(
            last.contains(&format!("-t{hp_ssh}:22")),
            "restarted argv adds the second forward: [{last}]"
        );
        assert!(
            poll_until(|| !pid_alive(first_pid), Duration::from_secs(5), "old passt exit"),
            "the replaced passt process must be terminated"
        );

        let _ = dp.delete_port(&serde_json::json!({"name": "vm1"}));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    // -- requirement 2: lifecycle wiring -------------------------------------

    /// R2: DeletePort stops that port's passt.
    #[test]
    fn delete_port_stops_the_port_passt() -> TestResult {
        // Poisoning-tolerant: a sibling test's red-phase panic must not
        // mask this test's own failure reason.
        let _path_lock = PASST_PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = passt_temp_root("life-del");
        std::fs::create_dir_all(&root)?;
        let _guard = install_passt_stub(&root, "plain")?;
        let (mut dp, _ip) = attached_dp(&root, "vm1", "02:00:00:00:00:01")?;

        let _hp = publish(&mut dp, "vm1", 6443);
        assert!(wait_invocations(&root, 1), "publish must ensure passt");
        let pid = passt_pids(&root).last().copied().expect("passt pid");
        assert!(pid_alive(pid), "passt must be running before delete");

        dp.delete_port(&serde_json::json!({"name": "vm1"}))
            .expect("delete_port ok");

        assert!(
            poll_until(|| !pid_alive(pid), Duration::from_secs(5), "passt exit after delete"),
            "DeletePort must stop the port's passt (pid {pid} still alive)"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    /// R2: DetachPort stops that port's passt too (the port left the
    /// segment; its WAN identity is gone).
    #[test]
    fn detach_port_stops_the_port_passt() -> TestResult {
        // Poisoning-tolerant: a sibling test's red-phase panic must not
        // mask this test's own failure reason.
        let _path_lock = PASST_PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = passt_temp_root("life-det");
        std::fs::create_dir_all(&root)?;
        let _guard = install_passt_stub(&root, "plain")?;
        let (mut dp, _ip) = attached_dp(&root, "vm1", "02:00:00:00:00:01")?;

        let _hp = publish(&mut dp, "vm1", 6443);
        assert!(wait_invocations(&root, 1), "publish must ensure passt");
        let pid = passt_pids(&root).last().copied().expect("passt pid");

        dp.detach_port(&serde_json::json!({"name": "vm1"}))
            .expect("detach_port ok");

        assert!(
            poll_until(|| !pid_alive(pid), Duration::from_secs(5), "passt exit after detach"),
            "DetachPort must stop the port's passt (pid {pid} still alive)"
        );
        let _ = dp.delete_port(&serde_json::json!({"name": "vm1"}));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    /// R2: a passt that exits on its own is noticed and re-ensured by the
    /// daemon (integration pin above the svc-crate unit-level respawn).
    #[test]
    fn daemon_reensures_passt_after_unexpected_exit() -> TestResult {
        // Poisoning-tolerant: a sibling test's red-phase panic must not
        // mask this test's own failure reason.
        let _path_lock = PASST_PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = passt_temp_root("life-crash");
        std::fs::create_dir_all(&root)?;
        std::fs::write(root.join("crash-now"), b"")?;
        let _guard = install_passt_stub(&root, "crash")?;
        let (mut dp, _ip) = attached_dp(&root, "vm1", "02:00:00:00:00:01")?;

        let _hp = publish(&mut dp, "vm1", 6443);
        assert!(
            wait_invocations(&root, 2),
            "daemon must notice the exited passt and re-ensure it (invocations: {})",
            argv_lines(&root).len()
        );
        let pids = passt_pids(&root);
        assert!(
            pids.windows(2).any(|w| w[0] != w[1]),
            "re-ensure must be a fresh process, not a zombie count"
        );

        // Stop the crash loop; the newest passt must stay alive.
        let _ = std::fs::remove_file(root.join("crash-now"));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let stable = passt_pids(&root).last().copied().map(pid_alive).unwrap_or(false);
            if stable {
                let p = passt_pids(&root).last().copied().expect("pid");
                std::thread::sleep(Duration::from_millis(400));
                if pid_alive(p) {
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no stable passt after crash loop ended"
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        let _ = dp.delete_port(&serde_json::json!({"name": "vm1"}));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    // -- requirement 3: gateway seam (pump level) ----------------------------

    /// R3 egress: a WAN-bound frame sent toward the gateway MAC is handed
    /// byte-identical to THIS port's passt fd; a frame addressed to a peer
    /// VM's MAC (L2 traffic, arbitrary dst IP included) never reaches passt.
    #[test]
    fn gateway_destined_frame_reaches_owning_port_passt_fd_only() -> TestResult {
        // Poisoning-tolerant: a sibling test's red-phase panic must not
        // mask this test's own failure reason.
        let _path_lock = PASST_PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = passt_temp_root("gw-egress");
        std::fs::create_dir_all(&root)?;
        let _guard = install_passt_stub(&root, "capture")?;
        let (mut dp, ip) = attached_dp(&root, "vm1", "02:00:00:00:00:09")?;
        // Publishing guarantees a running passt regardless of whether the
        // implementation ensures at attach or at publish time.
        let _hp = publish(&mut dp, "vm1", 6443);
        assert!(wait_invocations(&root, 1), "passt must be running for the fd test");

        let fe = FakeFrontend::connect(root.join("vm1.sock"))?;
        let mem = fe.mem().clone();
        let src_ip = ipv4_octets(&ip);

        // Local frame: addressed to a peer VM's MAC (in-CIDR destination), must
        // bypass passt entirely.
        let mut local_ip = ipv4_header(src_ip, [192, 168, 124, 50], 24, 17);
        local_ip.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let local = eth_frame(&DP_PEER_MAC, &DP_VM_MAC, 0x0800, &local_ip);

        // WAN frame: addressed to the gateway MAC (default router), outbound.
        let mut wan_ip = ipv4_header(src_ip, [8, 8, 8, 8], 24, 17);
        wan_ip.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let wan = eth_frame(&DP_GW_MAC, &DP_VM_MAC, 0x0800, &wan_ip);

        let tx_addr = GUEST_BASE + DATA_OFFSET;
        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&local), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            (local.len() + VNET_HDR_LEN) as u32,
            0,
        )?;
        // Negative window: give a wrongly-wired pump ample time to leak it.
        std::thread::sleep(Duration::from_millis(500));
        let leaked_local = std::fs::read(root.join("egress.bin"))
            .map(|b| passt_frames(&b).iter().any(|f| *f == local))
            .unwrap_or(false);
        assert!(!leaked_local, "local (in-CIDR) frame must not reach passt");

        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&wan), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            6,
            tx_addr,
            (wan.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let got = poll_until(
            || {
                std::fs::read(root.join("egress.bin"))
                    .map(|b| passt_frames(&b).iter().any(|f| *f == wan))
                    .unwrap_or(false)
            },
            Duration::from_secs(5),
            "wan frame in passt fd capture",
        );
        assert!(got, "gateway-destined frame must be written to the port's passt fd");

        let final_buf = std::fs::read(root.join("egress.bin")).unwrap_or_default();
        assert!(
            !passt_frames(&final_buf).iter().any(|f| *f == local),
            "local frame must never appear in the passt capture"
        );

        drop(fe);
        let _ = dp.delete_port(&serde_json::json!({"name": "vm1"}));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    /// R3 ingress: a frame the passt writes into its served fd (vnet
    /// ingress-framed) is injected into the OWNING port's virtqueue.
    #[test]
    fn passt_inbound_frame_injected_into_owning_port_virtqueue() -> TestResult {
        // Poisoning-tolerant: a sibling test's red-phase panic must not
        // mask this test's own failure reason.
        let _path_lock = PASST_PATH_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let root = passt_temp_root("gw-ingress");
        std::fs::create_dir_all(&root)?;
        let _guard = install_passt_stub(&root, "pipe")?;
        let (mut dp, _ip) = attached_dp(&root, "vm1", "02:00:00:00:00:09")?;
        let _hp = publish(&mut dp, "vm1", 6443);
        assert!(wait_invocations(&root, 1), "passt must be running for the fd test");

        let fe = FakeFrontend::connect(root.join("vm1.sock"))?;
        let mem = fe.mem().clone();

        // Post the device-writable RX buffer before cueing the stub write,
        // so the injected frame has a parked buffer to land in.
        let rx_addr = GUEST_BASE + DATA_OFFSET + 0x1000;
        {
            use vm_memory::Bytes;
            mem.write_slice(&[0u8; 128], vm_memory::GuestAddress(rx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 6, rx_addr, 128, 2)?;

        std::fs::write(root.join("inbound-cue"), b"")?;

        // Must match the stub's hardcoded frame exactly: ethernet header
        // dst 02:00:00:00:00:01 src 02:00:c0:a8:7c:01 type 0x0800 + 32 'A'.
        let mut expected = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        expected.extend_from_slice(&DP_GW_MAC);
        expected.extend_from_slice(&0x0800u16.to_be_bytes());
        expected.extend(std::iter::repeat(b'A').take(32));

        let got = wait_frame(&mem, rx_addr, Duration::from_secs(5))?;
        assert_eq!(
            decode_driver_rx(&got)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on delivered frame")?,
            expected,
            "passt inbound frame must reach the owning port intact"
        );

        drop(fe);
        let _ = dp.delete_port(&serde_json::json!({"name": "vm1"}));
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    // -- requirement 4: DHCP/DNS seam (pump level) ---------------------------

    /// Gateway presence: an ICMP echo request addressed to the gateway IP
    /// is answered with a well-formed echo reply (REQ-007).
    #[test]
    fn gateway_icmp_echo_request_yields_echo_reply() -> TestResult {
        let dir = passt_temp_root("icmp");
        std::fs::create_dir_all(&dir)?;
        let (mut dp, ip) = attached_dp(&dir, "vm9", "02:00:00:00:00:09")?;
        let reserved = ipv4_octets(&ip);

        let fe = FakeFrontend::connect(dir.join("vm9.sock"))?;
        let mem = fe.mem().clone();

        let tx_addr = GUEST_BASE + DATA_OFFSET;
        let rx0 = GUEST_BASE + DATA_OFFSET + 0x1000;
        {
            use vm_memory::Bytes;
            mem.write_slice(&[0u8; 128], vm_memory::GuestAddress(rx0))?;
        }

        // ICMP echo request to the gateway IP, behind the vnet header.
        let mut icmp = vec![ICMP_ECHO_REQUEST, 0, 0, 0, 0x12, 0x34, 0, 1];
        icmp.extend_from_slice(b"payload");
        let icmp_sum = inet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&icmp_sum.to_be_bytes());
        let iph = ipv4_header(reserved, DP_GW_IP_OCTETS, (20 + icmp.len()) as u16, IPPROTO_ICMP);
        let mut pkt = iph.clone();
        pkt.extend_from_slice(&icmp);
        // Fix the IPv4 checksum the helper leaves at zero.
        pkt[10..12].copy_from_slice(&[0, 0]);
        let ip_sum = inet_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        let request = eth_frame(&DP_GW_MAC, &DP_VM_MAC, ETHERTYPE_IPV4, &pkt);

        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&request), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 6, rx0, 128, 2)?;
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            (request.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let reply_len = wait_used_elem_len(&mem, 0, Duration::from_secs(5))? as usize;
        assert!(
            reply_len >= VNET_HDR_LEN + 14 + 20 + 8,
            "no ICMP reply reached the VM ({reply_len} bytes)"
        );
        let mut buf = vec![0u8; reply_len];
        vm_memory::Bytes::read_slice(&mem, &mut buf, vm_memory::GuestAddress(rx0))?;
        let frame = decode_driver_rx(&buf).ok_or("no vnet header on ICMP reply")?;

        assert_eq!(&frame[0..6], &DP_VM_MAC, "reply addressed to the VM");
        assert_eq!(&frame[6..12], &DP_GW_MAC, "reply sourced from the gateway MAC");
        let ihl = usize::from(frame[14] & 0x0f) * 4;
        assert_eq!(&frame[14..16], &[0x45, 0]);
        assert_eq!(
            &frame[16..18],
            &(20 + icmp.len() as u16).to_be_bytes(),
            "total length; frame={:02x?}",
            &frame[..reply_len.min(64)]
        );
        assert_eq!(&frame[26..30], &DP_GW_IP_OCTETS, "IP src must be the gateway");
        assert_eq!(
            &frame[30..34],
            &reserved,
            "IP dst must be the VM; frame={:02x?}",
            &frame[..reply_len.min(64)]
        );
        let icmp_reply = &frame[14 + ihl..];
        assert_eq!(icmp_reply[0], ICMP_ECHO_REPLY, "type must be echo reply");
        assert_eq!(&icmp_reply[4..6], &[0x12, 0x34], "identifier echoed");
        assert_eq!(&icmp_reply[6..8], &[0, 1], "sequence echoed");
        assert_eq!(&icmp_reply[8..], b"payload", "payload echoed");
        // Receiver invariant: the one's-complement sum over a segment with
        // a valid checksum field is 0xffff, which inverts to zero.
        assert_eq!(
            inet_checksum(icmp_reply),
            0,
            "ICMP checksum must verify; icmp={:02x?} framelen={}",
            icmp_reply,
            reply_len
        );
        assert_eq!(inet_checksum(&frame[14..14 + ihl]), 0, "IPv4 checksum must verify");

        drop(fe);
        let _ = dp.delete_port(&serde_json::json!({"name": "vm9"}));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// R4: a DHCP DISCOVER emitted on an attached port yields an OFFER and
    /// then an ACK carrying the port's reserved IP, the gateway as router,
    /// and the gateway IP as DNS (REQ-005).
    #[test]
    fn dhcp_discover_on_attached_port_yields_offer_then_ack_with_reserved_ip_gateway_dns() -> TestResult {
        let dir = passt_temp_root("dhcp");
        std::fs::create_dir_all(&dir)?;
        let (mut dp, ip) = attached_dp(&dir, "vm9", "02:00:00:00:00:09")?;
        let reserved = ipv4_octets(&ip);

        let fe = FakeFrontend::connect(dir.join("vm9.sock"))?;
        let mem = fe.mem().clone();

        let tx_addr = GUEST_BASE + DATA_OFFSET;
        let rx0 = GUEST_BASE + DATA_OFFSET + 0x1000;
        let rx1 = GUEST_BASE + DATA_OFFSET + 0x1800;
        {
            use vm_memory::Bytes;
            mem.write_slice(&[0u8; 512], vm_memory::GuestAddress(rx0))?;
            mem.write_slice(&[0u8; 512], vm_memory::GuestAddress(rx1))?;
        }

        // DISCOVER -> OFFER.
        let discover = udp_over_eth(
            &[0xff; 6],
            &DP_VM_MAC,
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            68,
            67,
            &dhcp_packet(1, 0x1122_3344, &DP_VM_MAC, None),
        );
        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&discover), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 6, rx0, 512, 2)?;
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            (discover.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let offer_len = wait_used_elem_len(&mem, 0, Duration::from_secs(5))? as usize;
        assert!(
            offer_len >= VNET_HDR_LEN + 14 + 20 + 8 + 240,
            "no DHCP OFFER reached the VM (RX completion carried {offer_len} bytes)"
        );
        let offer_frame = {
            use vm_memory::Bytes;
            let mut buf = vec![0u8; offer_len];
            mem.read_slice(&mut buf, vm_memory::GuestAddress(rx0))?;
            decode_driver_rx(&buf)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on OFFER")?
        };
        let offer = parse_dhcp_reply(&offer_frame).expect("OFFER frame with a DHCP payload");
        assert_eq!(offer.msg_type, Some(2), "first reply must be an OFFER");
        assert_eq!(offer.yiaddr, reserved, "OFFER must carry the port's reserved IP");
        assert_eq!(offer.router, Some(DP_GW_IP_OCTETS), "router option must be the gateway");
        assert_eq!(offer.dns, Some(DP_GW_IP_OCTETS), "DNS option must be the gateway IP");

        // REQUEST -> ACK.
        let request = udp_over_eth(
            &[0xff; 6],
            &DP_VM_MAC,
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            68,
            67,
            &dhcp_packet(3, 0x1122_3344, &DP_VM_MAC, Some(reserved)),
        );
        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&request), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 7, rx1, 512, 2)?;
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            6,
            tx_addr,
            (request.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let ack_len = wait_used_elem_len(&mem, 1, Duration::from_secs(5))? as usize;
        assert!(
            ack_len >= VNET_HDR_LEN + 14 + 20 + 8 + 240,
            "no DHCP ACK reached the VM (RX completion carried {ack_len} bytes)"
        );
        let ack_frame = {
            use vm_memory::Bytes;
            let mut buf = vec![0u8; ack_len];
            mem.read_slice(&mut buf, vm_memory::GuestAddress(rx1))?;
            decode_driver_rx(&buf)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on ACK")?
        };
        let ack = parse_dhcp_reply(&ack_frame).expect("ACK frame with a DHCP payload");
        assert_eq!(ack.msg_type, Some(5), "second reply must be an ACK");
        assert_eq!(ack.yiaddr, reserved, "ACK must carry the port's reserved IP");
        assert_eq!(ack.router, Some(DP_GW_IP_OCTETS), "router option must be the gateway");
        assert_eq!(ack.dns, Some(DP_GW_IP_OCTETS), "DNS option must be the gateway IP");

        drop(fe);
        let _ = dp.delete_port(&serde_json::json!({"name": "vm9"}));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    // >>> TASK-004-DHCP-ADDRESSING (red phase). Pins the DHCP reply
    // addressing fix: OFFER/ACK/NAK must be Ethernet-addressed to the DHCP
    // packet's sender MAC (the guest's actual NIC), not unconditionally to
    // the port's pinned MAC; a NAK (yiaddr 0.0.0.0) must go to the Ethernet
    // broadcast address so a guest whose NIC MAC differs still receives it.
    // Non-DHCP service replies keep the pinned-MAC addressing (see the DNS
    // test below). Red modes: the OFFER/ACK/NAK tests are runtime-red today
    // (service_reply/wrap_udp_reply address every reply to lp.mac); the
    // wrap_udp_reply seam test is runtime-red on the Ethernet destination.

    /// Req 1 + edge: a DHCP DISCOVER whose Ethernet source differs from the
    /// port's pinned MAC must be answered with an OFFER Ethernet-addressed
    /// to THAT sender MAC (the guest's actual NIC), not to lp.mac.
    #[test]
    fn dhcp_offer_addressed_to_sender_mac_when_different_from_port_mac() -> TestResult {
        let dir = passt_temp_root("dhcp-offer-sender");
        std::fs::create_dir_all(&dir)?;
        let (mut dp, _ip) = attached_dp(&dir, "vm9", "02:00:00:00:00:09")?;

        let fe = FakeFrontend::connect(dir.join("vm9.sock"))?;
        let mem = fe.mem().clone();

        let tx_addr = GUEST_BASE + DATA_OFFSET;
        let rx0 = GUEST_BASE + DATA_OFFSET + 0x1000;
        {
            use vm_memory::Bytes;
            mem.write_slice(&[0u8; 512], vm_memory::GuestAddress(rx0))?;
        }

        // The guest's actual NIC MAC (02:00:00:00:00:0a) differs from the
        // port's pinned MAC (02:00:00:00:00:09). The DISCOVER's Ethernet
        // source and chaddr are the guest MAC; the OFFER must be
        // Ethernet-addressed to that MAC so the guest's NIC accepts it.
        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
        let discover = udp_over_eth(
            &[0xff; 6],
            &guest_mac,
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            68,
            67,
            &dhcp_packet(1, 0x1122_3344, &guest_mac, None),
        );
        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&discover), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 6, rx0, 512, 2)?;
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            (discover.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let offer_len = wait_used_elem_len(&mem, 0, Duration::from_secs(5))? as usize;
        assert!(
            offer_len >= VNET_HDR_LEN + 14 + 20 + 8 + 240,
            "no DHCP OFFER reached the VM (RX completion carried {offer_len} bytes)"
        );
        let offer_frame = {
            use vm_memory::Bytes;
            let mut buf = vec![0u8; offer_len];
            mem.read_slice(&mut buf, vm_memory::GuestAddress(rx0))?;
            decode_driver_rx(&buf)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on OFFER")?
        };
        let offer = parse_dhcp_reply(&offer_frame).expect("OFFER frame with a DHCP payload");
        assert_eq!(offer.msg_type, Some(2), "first reply must be an OFFER");
        assert_ne!(offer.yiaddr, [0, 0, 0, 0], "OFFER must carry an address (unicast path)");
        assert_eq!(
            &offer_frame[0..6],
            &guest_mac,
            "OFFER must be Ethernet-addressed to the DHCP sender MAC, not the port's pinned MAC"
        );
        assert_ne!(
            &offer_frame[0..6],
            &DP_VM_MAC,
            "OFFER must not be addressed to the port's pinned MAC"
        );

        drop(fe);
        let _ = dp.delete_port(&serde_json::json!({"name": "vm9"}));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Req 1 + edge: the normal ACK path (yiaddr set) must also be unicast
    /// to the DHCP sender MAC when it differs from the port's pinned MAC.
    #[test]
    fn dhcp_ack_addressed_to_sender_mac_when_different_from_port_mac() -> TestResult {
        let dir = passt_temp_root("dhcp-ack-sender");
        std::fs::create_dir_all(&dir)?;
        let (mut dp, _ip) = attached_dp(&dir, "vm9", "02:00:00:00:00:09")?;

        // Reserve an IP for the guest's actual NIC MAC so the REQUEST can be
        // ACK'd: the DHCP wiring clones the IPAM per exchange (independent
        // snapshot), so a DISCOVER-time allocation would not persist to the
        // REQUEST's fresh server.
        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
        let guest_ip = dp
            .allocate_ip(&serde_json::json!({"network": "net0", "mac": "02:00:00:00:00:0a"}))
            .map_err(|e| format!("allocate_ip: {e:?}"))?;
        let guest_reserved = ipv4_octets(guest_ip.as_str().expect("bare ip string"));

        let fe = FakeFrontend::connect(dir.join("vm9.sock"))?;
        let mem = fe.mem().clone();

        let tx_addr = GUEST_BASE + DATA_OFFSET;
        let rx0 = GUEST_BASE + DATA_OFFSET + 0x1000;
        let rx1 = GUEST_BASE + DATA_OFFSET + 0x1800;
        {
            use vm_memory::Bytes;
            mem.write_slice(&[0u8; 512], vm_memory::GuestAddress(rx0))?;
            mem.write_slice(&[0u8; 512], vm_memory::GuestAddress(rx1))?;
        }

        // DISCOVER -> OFFER (yiaddr set).
        let discover = udp_over_eth(
            &[0xff; 6],
            &guest_mac,
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            68,
            67,
            &dhcp_packet(1, 0x1122_3344, &guest_mac, None),
        );
        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&discover), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 6, rx0, 512, 2)?;
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            (discover.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let offer_len = wait_used_elem_len(&mem, 0, Duration::from_secs(5))? as usize;
        assert!(
            offer_len >= VNET_HDR_LEN + 14 + 20 + 8 + 240,
            "no DHCP OFFER reached the VM (RX completion carried {offer_len} bytes)"
        );
        let offer_frame = {
            use vm_memory::Bytes;
            let mut buf = vec![0u8; offer_len];
            mem.read_slice(&mut buf, vm_memory::GuestAddress(rx0))?;
            decode_driver_rx(&buf)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on OFFER")?
        };
        let offer = parse_dhcp_reply(&offer_frame).expect("OFFER frame with a DHCP payload");
        assert_eq!(offer.msg_type, Some(2), "first reply must be an OFFER");
        assert_eq!(
            offer.yiaddr, guest_reserved,
            "OFFER must carry the guest MAC's reservation"
        );

        // REQUEST -> ACK (yiaddr set).
        let request = udp_over_eth(
            &[0xff; 6],
            &guest_mac,
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            68,
            67,
            &dhcp_packet(3, 0x1122_3344, &guest_mac, Some(offer.yiaddr)),
        );
        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&request), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 7, rx1, 512, 2)?;
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            6,
            tx_addr,
            (request.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let ack_len = wait_used_elem_len(&mem, 1, Duration::from_secs(5))? as usize;
        assert!(
            ack_len >= VNET_HDR_LEN + 14 + 20 + 8 + 240,
            "no DHCP ACK reached the VM (RX completion carried {ack_len} bytes)"
        );
        let ack_frame = {
            use vm_memory::Bytes;
            let mut buf = vec![0u8; ack_len];
            mem.read_slice(&mut buf, vm_memory::GuestAddress(rx1))?;
            decode_driver_rx(&buf)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on ACK")?
        };
        let ack = parse_dhcp_reply(&ack_frame).expect("ACK frame with a DHCP payload");
        assert_eq!(ack.msg_type, Some(5), "second reply must be an ACK");
        assert_eq!(ack.yiaddr, offer.yiaddr, "ACK must carry the offered address");
        assert_eq!(
            &ack_frame[0..6],
            &guest_mac,
            "ACK must be Ethernet-addressed to the DHCP sender MAC, not the port's pinned MAC"
        );
        assert_ne!(
            &ack_frame[0..6],
            &DP_VM_MAC,
            "ACK must not be addressed to the port's pinned MAC"
        );

        drop(fe);
        let _ = dp.delete_port(&serde_json::json!({"name": "vm9"}));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Req 2 + edge: a REQUEST that yields a NAK (yiaddr 0.0.0.0) must be
    /// answered with an Ethernet-broadcast frame so a guest whose NIC MAC
    /// differs from the port's pinned MAC still receives the NAK.
    #[test]
    fn dhcp_nak_uses_ethernet_broadcast() -> TestResult {
        let dir = passt_temp_root("dhcp-nak-bcast");
        std::fs::create_dir_all(&dir)?;
        let (mut dp, ip) = attached_dp(&dir, "vm9", "02:00:00:00:00:09")?;
        let reserved = ipv4_octets(&ip);

        let fe = FakeFrontend::connect(dir.join("vm9.sock"))?;
        let mem = fe.mem().clone();

        let tx_addr = GUEST_BASE + DATA_OFFSET;
        let rx0 = GUEST_BASE + DATA_OFFSET + 0x1000;
        {
            use vm_memory::Bytes;
            mem.write_slice(&[0u8; 512], vm_memory::GuestAddress(rx0))?;
        }

        // The guest's NIC MAC differs from the port's pinned MAC; it
        // REQUESTs the IP reserved to the port's pinned MAC, which the
        // server NAKs (the requested IP is not bound to the requesting
        // chaddr). The NAK's yiaddr is 0.0.0.0, so the reply must be
        // Ethernet-broadcast.
        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
        let request = udp_over_eth(
            &[0xff; 6],
            &guest_mac,
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            68,
            67,
            &dhcp_packet(3, 0x1122_3344, &guest_mac, Some(reserved)),
        );
        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&request), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 6, rx0, 512, 2)?;
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            (request.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let nak_len = wait_used_elem_len(&mem, 0, Duration::from_secs(5))? as usize;
        assert!(
            nak_len >= VNET_HDR_LEN + 14 + 20 + 8 + 240,
            "no DHCP NAK reached the VM (RX completion carried {nak_len} bytes)"
        );
        let nak_frame = {
            use vm_memory::Bytes;
            let mut buf = vec![0u8; nak_len];
            mem.read_slice(&mut buf, vm_memory::GuestAddress(rx0))?;
            decode_driver_rx(&buf)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on NAK")?
        };
        let nak = parse_dhcp_reply(&nak_frame).expect("NAK frame with a DHCP payload");
        assert_eq!(nak.msg_type, Some(6), "reply must be a NAK");
        assert_eq!(nak.yiaddr, [0, 0, 0, 0], "a NAK must not carry an address");
        assert_eq!(
            &nak_frame[0..6],
            &[0xff; 6],
            "NAK must be Ethernet-broadcast (ff:ff:ff:ff:ff:ff) so a guest whose NIC MAC differs still receives it"
        );
        assert_eq!(
            &nak_frame[30..34],
            &[255, 255, 255, 255],
            "NAK must keep the IP-broadcast destination"
        );
        assert_eq!(
            &nak_frame[26..30],
            &DP_GW_IP_OCTETS,
            "NAK must keep the gateway as the IP source (a broadcast source is dropped as martian)"
        );

        drop(fe);
        let _ = dp.delete_port(&serde_json::json!({"name": "vm9"}));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Edge (defensive path): at the addressing seam, an unspecified reply
    /// IP (yiaddr 0.0.0.0, e.g. a NAK) must produce an Ethernet-broadcast
    /// frame regardless of the MAC passed in. The sender-MAC parse failure
    /// itself is unreachable through the full stack (a DHCP request that
    /// reaches the handler is always >= 14+20+8+240 bytes, so the Ethernet
    /// source is always present); this pins the defensive broadcast at the
    /// seam that the fix must implement.
    #[test]
    fn wrap_udp_reply_broadcasts_ethernet_when_reply_ip_unspecified() {
        let frame = wrap_udp_reply(
            &[0u8; 240],
            MacAddr::from_bytes(DP_VM_MAC),
            Ipv4Addr::new(192, 168, 124, 1),
            Ipv4Addr::UNSPECIFIED,
            DHCP_SERVER_PORT,
            DHCP_CLIENT_PORT,
        );
        assert_eq!(
            &frame[0..6],
            &[0xff; 6],
            "an unspecified reply IP must yield an Ethernet-broadcast destination"
        );
        assert_eq!(
            &frame[30..34],
            &[255, 255, 255, 255],
            "an unspecified reply IP must keep the IP-broadcast destination"
        );
        assert_eq!(
            &frame[26..30],
            &[192, 168, 124, 1],
            "an unspecified reply IP must keep the gateway as the IP source (a broadcast source is dropped as martian)"
        );
    }

    // >>> TASK-004-DNS-SEAM (compile-red until Dataplane::set_dns_upstreams lands)

    /// Upstream stub for the DNS seam: records every relayed query and
    /// answers with the same bytes, QR flag set (a valid response echoing
    /// the query ID, which the forwarder relays byte-for-byte).
    struct RecordingUpstream {
        sent: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl k8netd_svc::dns::UpstreamSender for RecordingUpstream {
        fn send(&self, query: &[u8]) -> Result<Vec<u8>, k8netd_svc::dns::UpstreamError> {
            self.sent.lock().expect("sent lock").push(query.to_vec());
            let mut resp = query.to_vec();
            if let Some(flags) = resp.get_mut(2) {
                *flags |= 0x80; // QR bit: this is a response
            }
            Ok(resp)
        }
    }

    /// R4: a DNS query addressed to the gateway IP is forwarded upstream and
    /// the upstream's answer is relayed back to the requesting port (REQ-006).
    #[test]
    fn dns_query_to_gateway_ip_is_forwarded_to_stub_upstream_and_answered() -> TestResult {
        let dir = passt_temp_root("dns");
        std::fs::create_dir_all(&dir)?;
        let (mut dp, ip) = attached_dp(&dir, "vm9", "02:00:00:00:00:09")?;
        let (upstream, sent) = {
            let shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                RecordingUpstream {
                    sent: std::sync::Arc::clone(&shared),
                },
                shared,
            )
        };
        // Pinned seam: inject the stub upstream into the daemon's forwarder.
        dp.set_dns_upstreams(vec![Box::new(upstream)]);

        let fe = FakeFrontend::connect(dir.join("vm9.sock"))?;
        let mem = fe.mem().clone();

        let tx_addr = GUEST_BASE + DATA_OFFSET;
        let rx0 = GUEST_BASE + DATA_OFFSET + 0x1000;
        {
            use vm_memory::Bytes;
            mem.write_slice(&[0u8; 512], vm_memory::GuestAddress(rx0))?;
        }

        let query = dns_query_bytes(0x4242);
        let qframe = udp_over_eth(
            &DP_GW_MAC,
            &DP_VM_MAC,
            ipv4_octets(&ip),
            DP_GW_IP_OCTETS,
            12345,
            53,
            &query,
        );
        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&qframe), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 6, rx0, 512, 2)?;
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            (qframe.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let reply_len = wait_used_elem_len(&mem, 0, Duration::from_secs(5))? as usize;
        assert!(
            reply_len >= VNET_HDR_LEN + 14 + 20 + 8,
            "no DNS reply reached the VM (RX completion carried {reply_len} bytes)"
        );
        let reply_frame = {
            use vm_memory::Bytes;
            let mut buf = vec![0u8; reply_len];
            mem.read_slice(&mut buf, vm_memory::GuestAddress(rx0))?;
            decode_driver_rx(&buf)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on DNS reply")?
        };

        // The stub upstream must have seen the exact query bytes.
        let seen = sent.lock().expect("sent lock").clone();
        assert_eq!(seen.len(), 1, "query forwarded upstream exactly once");
        assert_eq!(seen[0], query, "query relayed byte-for-byte");

        // The answer relayed to the VM carries the QR-flipped query bytes.
        let ihl = usize::from(reply_frame[14] & 0x0f) * 4;
        let dns_payload = &reply_frame[14 + ihl + 8..];
        let mut expected = query.clone();
        expected[2] |= 0x80;
        assert_eq!(
            dns_payload,
            &expected[..],
            "upstream answer relayed byte-for-byte to the VM"
        );

        drop(fe);
        let _ = dp.delete_port(&serde_json::json!({"name": "vm9"}));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Req 3 + edge: a non-DHCP service reply (DNS) must keep the current
    /// addressing — Ethernet destination = the port's pinned MAC — even when
    /// the query's Ethernet source differs from lp.mac. The DHCP sender-MAC
    /// addressing must not leak into the non-DHCP path.
    #[test]
    fn dns_reply_keeps_port_mac_addressing_for_non_dhcp() -> TestResult {
        let dir = passt_temp_root("dns-lpmac");
        std::fs::create_dir_all(&dir)?;
        let (mut dp, _ip) = attached_dp(&dir, "vm9", "02:00:00:00:00:09")?;
        let (upstream, _sent) = {
            let shared = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                RecordingUpstream {
                    sent: std::sync::Arc::clone(&shared),
                },
                shared,
            )
        };
        dp.set_dns_upstreams(vec![Box::new(upstream)]);

        let fe = FakeFrontend::connect(dir.join("vm9.sock"))?;
        let mem = fe.mem().clone();

        let tx_addr = GUEST_BASE + DATA_OFFSET;
        let rx0 = GUEST_BASE + DATA_OFFSET + 0x1000;
        {
            use vm_memory::Bytes;
            mem.write_slice(&[0u8; 512], vm_memory::GuestAddress(rx0))?;
        }

        // The query's Ethernet source is a guest MAC that differs from the
        // port's pinned MAC; the DNS answer must still be addressed to the
        // pinned MAC (non-DHCP addressing is unchanged).
        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x0a];
        let query = dns_query_bytes(0x4242);
        let qframe = udp_over_eth(
            &DP_GW_MAC,
            &guest_mac,
            [192, 168, 124, 150],
            DP_GW_IP_OCTETS,
            12345,
            53,
            &query,
        );
        {
            use vm_memory::Bytes;
            mem.write_slice(&encode_driver_tx(&qframe), vm_memory::GuestAddress(tx_addr))?;
        }
        post_desc_and_kick(&mem, fe.kick_fd(RX_VRING), RX_VRING, 6, rx0, 512, 2)?;
        post_desc_and_kick(
            &mem,
            fe.kick_fd(TX_VRING),
            TX_VRING,
            5,
            tx_addr,
            (qframe.len() + VNET_HDR_LEN) as u32,
            0,
        )?;

        let reply_len = wait_used_elem_len(&mem, 0, Duration::from_secs(5))? as usize;
        assert!(
            reply_len >= VNET_HDR_LEN + 14 + 20 + 8,
            "no DNS reply reached the VM (RX completion carried {reply_len} bytes)"
        );
        let reply_frame = {
            use vm_memory::Bytes;
            let mut buf = vec![0u8; reply_len];
            mem.read_slice(&mut buf, vm_memory::GuestAddress(rx0))?;
            decode_driver_rx(&buf)
                .map(|f| f.to_vec())
                .ok_or("no vnet header on DNS reply")?
        };
        assert_eq!(
            &reply_frame[0..6],
            &DP_VM_MAC,
            "non-DHCP reply must keep the port's pinned MAC as the Ethernet destination"
        );
        assert_eq!(
            &reply_frame[30..34],
            &[192, 168, 124, 150],
            "DNS reply must be IP-addressed to the query's source IP"
        );

        drop(fe);
        let _ = dp.delete_port(&serde_json::json!({"name": "vm9"}));
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    // <<< TASK-004-DNS-SEAM
}
