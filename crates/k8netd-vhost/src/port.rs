//! vhost-user backend port serving one cloud-hypervisor NIC
//! (spec REQ-003, REQ-009, REQ-010; plan TASK-019).
//!
//! One port = one listening Unix socket + one `VhostUserDaemon` running a
//! [`NetBackend`] (single queue pair, REQ-009). The accept/re-listen loop
//! rebinds after every frontend disconnect, including abrupt mid-session
//! drops, and unlinks stale socket files before bind (REQ-010).
//!
//! Frame paths over the single negotiated vring:
//! - egress (VM -> switch): readable descriptor chains are drained and each
//!   frame published on the sink as [`PortMessage::FromVm`];
//! - ingress (switch -> VM): writable chains are parked, filled from the next
//!   injected [`PortMessage::ToVm`], marked used, and the call fd signalled.
//!
//! Frames are raw Ethernet; no virtio-net header (pinned by the TASK-018
//! test contract).

use std::io::Write as _;
use std::io::{self, Read as _};
use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use vhost::vhost_user::Listener;
use vhost::vhost_user::message::VhostUserProtocolFeatures;
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, VringMutex, VringT};
use virtio_queue::{QueueOwnedT, Reader, Writer};
use vm_memory::{Bytes, GuestAddress, GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
use vmm_sys_util::epoll::EventSet;

/// Queue pairs served; pinned to one by REQ-009.
const NUM_QUEUES: usize = 1;
/// Maximum descriptor count per queue.
const QUEUE_SIZE: u16 = 256;
/// VIRTIO_F_VERSION_1 feature bit (bit 32), mandatory for virtio 1.0+.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;
/// VHOST_USER_F_PROTOCOL_FEATURES (bit 30): gates protocol-feature msgs.
const VHOST_USER_PROTOCOL: u64 = 1 << 30;
/// Split-virtqueue descriptor flag: device-writable buffer.
const VIRTQ_DESC_F_WRITE: u16 = 2;
/// How long the device waits for an injected frame per posted RX buffer.
const INJECT_WAIT: Duration = Duration::from_millis(500);

/// Frames exchanged between the port and the switch engine.
#[derive(Debug)]
pub enum PortMessage {
    /// Injected by the switch: deliver this frame to the VM through the virtqueue.
    ToVm(Vec<u8>),
    /// Read by the port from the VM's virtqueue: hand to the switch.
    FromVm(Vec<u8>),
}

/// Bidirectional frame channel between the switch and one port.
///
/// Field perspective is the PORT's (the vhost-user backend endpoint):
/// - `tx`: port -> switch side. Frames read off the VM's virtqueue are
///   sent here ([`PortMessage::FromVm`]).
/// - `rx`: switch side -> port. Frames injected by the switch
///   ([`PortMessage::ToVm`]) are received here and placed into posted
///   device-writable buffers.
///
/// Ownership: the port OWNS both ends it is given. Callers keep their own
/// channel ends (the receiver of a separate delivery pair to observe
/// `FromVm`, and a sender of a separate injection pair to send `ToVm`) --
/// the port never hands back or shares the ends passed in `sink`.
pub struct PortSink {
    /// Port -> switch: frames emitted by the VM (delivery path).
    pub tx: Sender<PortMessage>,
    /// Switch -> port: frames destined for the VM (injection path).
    pub rx: Receiver<PortMessage>,
}

/// Minimal virtio-net device state driven by the vhost-user event loop.
///
/// Holds the guest memory published by the frontend plus the sink ends; all
/// fields are behind `Arc`/`Mutex` so the backend satisfies the `Clone +
/// Send + Sync` bounds `VhostUserDaemon` requires.
#[derive(Clone)]
struct NetBackend {
    mem: Arc<Mutex<Option<GuestMemoryAtomic<GuestMemoryMmap<()>>>>>,
    rx: Arc<Mutex<Receiver<PortMessage>>>,
    tx: Sender<PortMessage>,
}

impl NetBackend {
    fn new(tx: Sender<PortMessage>, rx: Receiver<PortMessage>) -> Self {
        NetBackend {
            mem: Arc::new(Mutex::new(None)),
            rx: Arc::new(Mutex::new(rx)),
            tx,
        }
    }
}

impl VhostUserBackend for NetBackend {
    type Bitmap = ();
    type Vring = VringMutex<GuestMemoryAtomic<GuestMemoryMmap<()>>>;

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        usize::from(QUEUE_SIZE)
    }

    fn features(&self) -> u64 {
        VIRTIO_F_VERSION_1 | VHOST_USER_PROTOCOL
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        // REPLY_ACK is honored natively by the handler; advertising it keeps
        // protocol-feature negotiation non-empty without extra obligations.
        VhostUserProtocolFeatures::REPLY_ACK
    }

    fn set_event_idx(&self, _enabled: bool) {}

    fn update_memory(&self, mem: GuestMemoryAtomic<GuestMemoryMmap<()>>) -> io::Result<()> {
        *self.mem.lock().expect("mem mutex poisoned") = Some(mem);
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        _evset: EventSet,
        vrings: &[Self::Vring],
        _thread_id: usize,
    ) -> io::Result<()> {
        if device_event != 0 {
            return Ok(());
        }
        let guard = match self.mem.lock().expect("mem mutex poisoned").as_ref() {
            Some(m) => m.memory(),
            None => return Ok(()),
        };
        // The region collection behind the guard is the GuestMemory.
        let snapshot = &*guard;

        // Collect available chains under a short-lived mutable guard; the
        // iterator borrows the queue, so it must be consumed here.
        let mut chains = Vec::new();
        let desc_table;
        {
            let mut st = vrings[0].get_mut();
            desc_table = st.get_queue().state().desc_table;
            match st.get_queue_mut().iter(snapshot) {
                Ok(iter) => chains.extend(iter),
                Err(_) => return Ok(()),
            }
        }

        let mut used: Vec<(u16, u32)> = Vec::with_capacity(chains.len());
        for chain in chains {
            let head = chain.head_index();
            // Classify by the head descriptor's flags (single-desc chains per
            // the pinned contract): readable = egress frame, writable = RX slot.
            let flags: u16 = if desc_table != 0 {
                snapshot
                    .read_obj(GuestAddress(desc_table + 16 * u64::from(head) + 12))
                    .unwrap_or(0)
            } else {
                0
            };
            if flags & VIRTQ_DESC_F_WRITE == 0 {
                // Egress: drain the readable bytes as one raw Ethernet frame.
                let mut reader = Reader::new(snapshot, chain).map_err(|e| io::Error::other(e.to_string()))?;
                let n = reader.available_bytes();
                let mut frame = vec![0u8; n];
                reader.read_exact(&mut frame)?;
                let _ = self.tx.send(PortMessage::FromVm(frame));
                used.push((head, n as u32));
            } else {
                // Ingress slot: wait briefly for an injected frame, fill the
                // writable buffer, report the exact written length.
                let mut writer = Writer::new(snapshot, chain).map_err(|e| io::Error::other(e.to_string()))?;
                let cap = writer.available_bytes();
                let got = self.rx.lock().expect("rx mutex poisoned").recv_timeout(INJECT_WAIT);
                match got {
                    Ok(PortMessage::ToVm(frame)) if frame.len() <= cap => {
                        writer.write_all(&frame)?;
                        used.push((head, frame.len() as u32));
                    }
                    _ => used.push((head, 0)),
                }
            }
        }

        for (idx, len) in &used {
            vrings[0]
                .add_used(*idx, *len)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        if !used.is_empty() {
            vrings[0].signal_used_queue()?;
        }
        Ok(())
    }
}

/// vhost-user backend port serving one cloud-hypervisor NIC.
pub struct VhostPort {}

impl VhostPort {
    /// Binds `socket_path` (unlinking any stale socket/file first, REQ-010)
    /// and serves connections in an accept/re-listen loop on a background
    /// thread: one frontend session at a time, re-binding for the next client
    /// after each disconnect, including abrupt mid-session drops.
    /// Returns once the socket is bound; `Err` only on bind failure
    /// (e.g. missing parent directory).
    pub fn new(socket_path: impl AsRef<Path>, _network_name: &str, sink: PortSink) -> io::Result<Self> {
        let path = socket_path.as_ref();

        // Fail cleanly before any thread spawns when the parent is missing.
        match path.parent() {
            Some(parent) if parent.exists() => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("missing parent directory for {}", path.display()),
                ));
            }
        }

        let backend = NetBackend::new(sink.tx, sink.rx);
        let mut listener = Listener::new(path, true).map_err(|e| io::Error::other(e.to_string()))?;

        // Accept/re-listen loop (REQ-010): one frontend session at a time.
        // A FRESH daemon (and therefore a fresh protocol handler) is built
        // per session: the handler rejects a second SET_OWNER ("already
        // claimed") otherwise. Backend state survives via shared Arcs.
        thread::spawn(move || {
            loop {
                let mut daemon = match VhostUserDaemon::new(
                    "k8netd-port".to_string(),
                    backend.clone(),
                    GuestMemoryAtomic::new(GuestMemoryMmap::<()>::new()),
                ) {
                    Ok(d) => d,
                    Err(_) => {
                        thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                };
                if daemon.start(&mut listener).is_err() {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }
                let _ = daemon.wait();
                // Tear the session down explicitly: Drop's blind conn.shutdown
                // wedges the shared listener for the next accept, so the daemon
                // is forgotten instead (backend state lives in shared Arcs).
                if let Some(sh) = daemon.shutdown_handle() {
                    sh.shutdown();
                }
                std::mem::forget(daemon);
            }
        });

        Ok(VhostPort {})
    }

    /// Number of virtqueue pairs served; pinned to 1 (REQ-009).
    #[allow(dead_code)] // exercised by the pinned test contract
    pub(crate) fn num_queues(&self) -> usize {
        NUM_QUEUES
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::RawFd;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use vm_memory::{Bytes, GuestAddress};

    use crate::fake_frontend::FakeFrontend;

    // RED PHASE: these names do not exist yet. TASK-019 implements them in
    // this module (above the tests) exactly as pinned in the module docs;
    // until then the test build fails to compile — the expected red state.
    use super::{PortMessage, PortSink, VhostPort};

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    type TOk<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    /// Upper bound for every wait in these tests.
    const TIMEOUT: Duration = Duration::from_secs(5);

    // Ring layout constants — must stay in sync with `fake_frontend.rs`
    // (they are private there, so the driver-side test code restates them).
    const GUEST_BASE: u64 = 0x1000_0000;
    const DESC_TABLE_OFFSET: u64 = 0x0;
    const USED_RING_OFFSET: u64 = 0x1_0000;
    const AVAIL_RING_OFFSET: u64 = 0x2_0000;
    /// Scratch area for frame buffers, past both rings.
    const DATA_OFFSET: u64 = 0x3_0000;
    const QUEUE_SIZE: u16 = 256;

    /// Split-virtqueue descriptor flag: device-writable buffer.
    const VIRTQ_DESC_F_WRITE: u16 = 2;

    static TMP_SEQ: AtomicU32 = AtomicU32::new(0);

    /// Unique short temp dir (socket paths must stay under sun_path limits).
    fn temp_root(tag: &str) -> PathBuf {
        let n = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("k8netd-vh-{tag}-{}-{n}", std::process::id()))
    }

    /// Blocks until the socket path exists or the deadline expires.
    fn wait_for_socket(path: &Path) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        while !path.exists() {
            if Instant::now() > deadline {
                panic!("socket {:?} never appeared", path);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    /// Writes one split-virtqueue descriptor (no NEXT chaining).
    fn write_desc(mem: &vm_memory::GuestMemoryMmap<()>, idx: u16, addr: u64, len: u32, flags: u16) -> TestResult {
        let base = GUEST_BASE + DESC_TABLE_OFFSET + u64::from(idx) * 16;
        mem.write_obj(addr.to_le_bytes(), GuestAddress(base))?;
        mem.write_obj(len.to_le_bytes(), GuestAddress(base + 8))?;
        mem.write_obj(flags.to_le_bytes(), GuestAddress(base + 12))?;
        mem.write_obj(0u16.to_le_bytes(), GuestAddress(base + 14))?;
        Ok(())
    }

    /// Driver side: appends `desc_idx` to the avail ring.
    fn push_avail(mem: &vm_memory::GuestMemoryMmap<()>, desc_idx: u16) -> TestResult {
        let idx_addr = GuestAddress(GUEST_BASE + AVAIL_RING_OFFSET + 2);
        let cur: u16 = mem.read_obj(idx_addr)?;
        let slot = GuestAddress(GUEST_BASE + AVAIL_RING_OFFSET + 4 + u64::from(cur % QUEUE_SIZE) * 2);
        mem.write_obj(desc_idx.to_le_bytes(), slot)?;
        mem.write_obj((cur + 1).to_le_bytes(), idx_addr)?;
        Ok(())
    }

    /// Rings the kick doorbell (driver -> device notification).
    fn kick(kick_fd: RawFd) -> TestResult {
        let val: u64 = 1;
        let n = unsafe {
            libc::write(
                kick_fd,
                &val as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        assert_eq!(n, 8, "kick write failed");
        Ok(())
    }

    /// Current device-published used-ring index.
    fn used_idx(mem: &vm_memory::GuestMemoryMmap<()>) -> TOk<u16> {
        Ok(mem.read_obj::<u16>(GuestAddress(GUEST_BASE + USED_RING_OFFSET + 2))?)
    }

    /// Used-ring element `i`: (descriptor id, written length).
    fn used_elem(mem: &vm_memory::GuestMemoryMmap<()>, i: u16) -> TOk<(u32, u32)> {
        let base = GUEST_BASE + USED_RING_OFFSET + 4 + u64::from(i) * 8;
        let id: u32 = mem.read_obj(GuestAddress(base))?;
        let len: u32 = mem.read_obj(GuestAddress(base + 4))?;
        Ok((id, len))
    }

    /// Waits until the device publishes a used element for `desc_id`.
    fn wait_used_len(mem: &vm_memory::GuestMemoryMmap<()>, desc_id: u32) -> TOk<u32> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let idx = used_idx(mem)?;
            for i in 0..idx {
                let (id, len) = used_elem(mem, i)?;
                if id == desc_id {
                    return Ok(len);
                }
            }
            if Instant::now() > deadline {
                panic!("device never used descriptor {desc_id}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Waits until the call eventfd becomes readable (device -> driver signal).
    fn wait_call(call_fd: RawFd) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let mut pfd = libc::pollfd {
                fd: call_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!("call eventfd never signalled");
            }
            let n = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as libc::c_int) };
            if n < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if n > 0 && pfd.revents & libc::POLLIN != 0 {
                return Ok(());
            }
        }
    }

    /// Minimal deterministic Ethernet frame (broadcast dst, src 02:00..).
    fn make_frame(payload_len: usize) -> Vec<u8> {
        let mut f = vec![0u8; 14 + payload_len];
        f[..6].copy_from_slice(&[0xff; 6]);
        f[6] = 0x02;
        for (i, b) in f.iter_mut().enumerate().skip(14) {
            *b = (i % 251) as u8;
        }
        f
    }

    /// Starts a port at `root/port.sock` and returns (path, sink rx, injector).
    fn spawn_port(
        root: &Path,
    ) -> TOk<(
        PathBuf,
        VhostPort,
        mpsc::Sender<PortMessage>,
        mpsc::Receiver<PortMessage>,
    )> {
        let sock = root.join("port.sock");
        // Two channel pairs: injection (test -> port) and delivery (port -> test).
        let (inject_tx, inject_rx) = mpsc::channel::<PortMessage>();
        let (deliver_tx, deliver_rx) = mpsc::channel::<PortMessage>();
        let port = VhostPort::new(
            &sock,
            "net0",
            PortSink {
                tx: deliver_tx,
                rx: inject_rx,
            },
        )?;
        wait_for_socket(&sock)?;
        Ok((sock, port, inject_tx, deliver_rx))
    }

    /// REQ-1 / VC-07: one full session — negotiate, map memfd, then exchange
    /// frames in both directions over the single queue pair.
    ///
    /// - VM -> switch: the driver (test) queues a frame descriptor and kicks;
    ///   the port must consume it and publish `FromVm(frame)` on the sink.
    /// - Switch -> VM: a `ToVm(frame)` injected via the sink must land in a
    ///   device-writable buffer, be marked used with the right length, and
    ///   raise the call eventfd.
    #[test]
    fn req1_full_session_frame_exchange() -> TestResult {
        let root = temp_root("req1");
        fs::create_dir_all(&root)?;
        let (sock, port, inject_tx, deliver_rx) = spawn_port(&root)?;
        assert_eq!(port.num_queues(), 1, "REQ-009 pins a single queue pair");

        let fe = FakeFrontend::connect(&sock)?;
        let mem = fe.mem();

        // --- VM -> switch -------------------------------------------------
        let out = make_frame(64);
        let out_addr = GUEST_BASE + DATA_OFFSET;
        mem.write_slice(&out, GuestAddress(out_addr))?;
        write_desc(mem, 0, out_addr, out.len() as u32, 0)?;
        push_avail(mem, 0)?;
        kick(fe.kick_fd())?;

        match deliver_rx.recv_timeout(TIMEOUT)? {
            PortMessage::FromVm(f) => assert_eq!(f, out, "frame corrupted in egress path"),
            PortMessage::ToVm(_) => panic!("unexpected ToVm message from port"),
        }

        // --- switch -> VM ---------------------------------------------------
        let inp = make_frame(96);
        let in_addr = GUEST_BASE + DATA_OFFSET + 0x1000;
        mem.write_slice(&[0u8; 128], GuestAddress(in_addr))?;
        write_desc(mem, 1, in_addr, 128, VIRTQ_DESC_F_WRITE)?;
        push_avail(mem, 1)?;
        kick(fe.kick_fd())?; // announce the freshly posted RX buffer

        inject_tx.send(PortMessage::ToVm(inp.clone()))?;

        let written = wait_used_len(mem, 1)?;
        assert_eq!(written as usize, inp.len(), "device must report the exact frame length");
        let mut buf = [0u8; 128];
        mem.read_slice(&mut buf, GuestAddress(in_addr))?;
        assert_eq!(&buf[..inp.len()], &inp[..], "frame corrupted in ingress path");
        wait_call(fe.call_fd())?;

        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// REQ-2 / REQ-010: after the first frontend disconnects (abruptly, with
    /// no close handshake), the port must re-listen so a second frontend can
    /// run a complete session against the same socket path.
    #[test]
    fn req2_relisten_after_disconnect() -> TestResult {
        let root = temp_root("req2");
        fs::create_dir_all(&root)?;
        let (sock, _port, _inject_tx, _deliver_rx) = spawn_port(&root)?;

        let fe1 = FakeFrontend::connect(&sock)?;
        assert_ne!(fe1.features(), 0, "first session negotiated features");
        drop(fe1); // abrupt mid-session disconnect

        // Give the accept loop time to notice EOF and re-bind.
        std::thread::sleep(Duration::from_millis(300));
        eprintln!("[t] slept, connecting fe2");
        wait_for_socket(&sock)?;

        let fe2 = FakeFrontend::connect(&sock)?;
        assert_ne!(fe2.features(), 0, "second session negotiated features");
        assert_ne!(
            fe2.protocol_features().bits(),
            0,
            "second session negotiated protocol features"
        );

        drop(fe2);
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// REQ-3 / REQ-010: a stale file left at the socket path (e.g. after a
    /// daemon crash) must be unlinked before bind; construction still
    /// succeeds and the path becomes a live, connectable socket.
    #[test]
    fn req3_stale_socket_unlinked_before_bind() -> TestResult {
        let root = temp_root("req3");
        fs::create_dir_all(&root)?;
        let sock = root.join("port.sock");
        fs::write(&sock, b"stale leftovers from a previous daemon")?;

        let (_port, _inject_tx, _deliver_rx) = {
            let (inject_tx, inject_rx) = mpsc::channel::<PortMessage>();
            let (deliver_tx, deliver_rx) = mpsc::channel::<PortMessage>();
            let port = VhostPort::new(
                &sock,
                "net0",
                PortSink {
                    tx: deliver_tx,
                    rx: inject_rx,
                },
            )?;
            (port, inject_tx, deliver_rx)
        };

        wait_for_socket(&sock)?;
        let fe = FakeFrontend::connect(&sock)?;
        assert_ne!(fe.features(), 0);

        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Edge: a client that connects but never negotiates (or aborts early)
    /// must not wedge the accept loop — a well-behaved frontend connecting
    /// afterwards still gets a complete session.
    #[test]
    fn edge_connect_without_negotiation_keeps_loop_alive() -> TestResult {
        let root = temp_root("edge-no-negotiation");
        fs::create_dir_all(&root)?;
        let (sock, _port, _inject_tx, _deliver_rx) = spawn_port(&root)?;

        // Connect and drop immediately: no SET_OWNER, nothing.
        let raw = UnixStream::connect(&sock)?;
        drop(raw);
        std::thread::sleep(Duration::from_millis(300));

        let fe = FakeFrontend::connect(&sock)?;
        assert_ne!(fe.features(), 0, "loop survived the aborted client");

        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Edge: binding under a missing parent directory fails cleanly with
    /// `Err` instead of panicking or spinning.
    #[test]
    fn edge_missing_parent_dir_fails_cleanly() {
        let (_inject_tx, inject_rx) = mpsc::channel::<PortMessage>();
        let (deliver_tx, _deliver_rx) = mpsc::channel::<PortMessage>();
        let result = VhostPort::new(
            "/proc/k8netd-test-nonexistent/nope.sock",
            "net0",
            PortSink {
                tx: deliver_tx,
                rx: inject_rx,
            },
        );
        assert!(result.is_err(), "missing parent dir must fail cleanly");
    }

    /// Edge: REQ-009 pins exactly one queue pair.
    #[test]
    fn edge_single_queue_pair_pinned() -> TestResult {
        let root = temp_root("edge-num-queues");
        fs::create_dir_all(&root)?;
        let (_sock, port, _inject_tx, _deliver_rx) = spawn_port(&root)?;
        assert_eq!(port.num_queues(), 1);
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }
}
