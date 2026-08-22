//! Tests for the vhost-user backend port (TASK-018 part 2; REQ-009, REQ-010, VC-07).
//!
//! RED PHASE: `VhostPort` does not exist yet. Compile errors naming `VhostPort`,
//! `PortSink`, or `PortMessage` are the EXPECTED failure mode. TASK-019
//! implements the production code above this test module to satisfy them.
//!
//! # Pinned production API (TASK-019 must provide exactly this shape)
//!
//! ```ignore
//! /// Frames exchanged between the port and the switch engine.
//! pub enum PortMessage {
//!     /// Injected by the switch: deliver this frame to the VM through the virtqueue.
//!     ToVm(Vec<u8>),
//!     /// Read by the port from the VM's virtqueue: hand to the switch.
//!     FromVm(Vec<u8>),
//! }
//!
//! /// Bidirectional frame channel between the switch and one port.
//! pub struct PortSink {
//!     /// Switch -> port: frames destined for the VM (injection path).
//!     pub tx: std::sync::mpsc::Sender<PortMessage>,
//!     /// Port -> switch: frames emitted by the VM (delivery path).
//!     pub rx: std::sync::mpsc::Receiver<PortMessage>,
//! }
//!
//! impl VhostPort {
//!     /// Binds `socket_path` (unlinking any stale socket/file first, REQ-010)
//!     /// and serves connections in an accept/re-listen loop on a background
//!     /// thread (REQ-010): one frontend session at a time, re-binding for the
//!     /// next client after each disconnect, including abrupt mid-session drops.
//!     /// Returns once the socket is bound; `Err` only on bind failure
//!     /// (e.g. missing parent directory).
//!     pub fn new(
//!         socket_path: impl AsRef<Path>,
//!         network_name: &str,
//!         sink: PortSink,
//!     ) -> std::io::Result<VhostPort>;
//!
//!     /// Number of virtqueue pairs served; pinned to 1 (REQ-009).
//!     pub fn num_queues(&self) -> usize;
//! }
//! ```
//!
//! Frame-exchange tests drive the single negotiated vring (vring 0) directly:
//! the test plays the driver side (writes descriptors + avail ring entries in
//! the shared memfd region, rings the kick doorbell), the port plays the
//! device side (consumes descriptors, writes the used ring, signals the call
//! eventfd). All waits are bounded by [`TIMEOUT`] so failures cannot hang CI.

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
                if u32::from(id) == desc_id {
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
        let (msg_tx, msg_rx) = mpsc::channel::<PortMessage>();
        let port = VhostPort::new(
            &sock,
            "net0",
            PortSink {
                tx: msg_tx.clone(),
                rx: msg_rx,
            },
        )?;
        wait_for_socket(&sock)?;
        Ok((sock, port, msg_tx, msg_rx))
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
        let (sock, port, msg_tx, msg_rx) = spawn_port(&root)?;
        assert_eq!(port.num_queues(), 1, "REQ-009 pins a single queue pair");

        let mut fe = FakeFrontend::connect(&sock)?;
        let mem = fe.mem();

        // --- VM -> switch -------------------------------------------------
        let out = make_frame(64);
        let out_addr = GUEST_BASE + DATA_OFFSET;
        mem.write_slice(&out, GuestAddress(out_addr))?;
        write_desc(mem, 0, out_addr, out.len() as u32, 0)?;
        push_avail(mem, 0)?;
        kick(fe.kick_fd())?;

        match msg_rx.recv_timeout(TIMEOUT)? {
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

        msg_tx.send(PortMessage::ToVm(inp.clone()))?;

        let written = wait_used_len(mem, 1)?;
        assert_eq!(written as usize, inp.len(), "device must report the exact frame length");
        let mut buf = [0u8; 128];
        mem.read_slice(&mut buf, GuestAddress(in_addr))?;
        assert_eq!(&buf[..inp.len()], &inp[..], "frame corrupted in ingress path");
        wait_call(fe.call_fd())?;

        drop(fe);
        drop(port);
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
        let (sock, _port, _tx, _rx) = spawn_port(&root)?;

        let fe1 = FakeFrontend::connect(&sock)?;
        assert_ne!(fe1.features(), 0, "first session negotiated features");
        drop(fe1); // abrupt mid-session disconnect

        // Give the accept loop time to notice EOF and re-bind.
        std::thread::sleep(Duration::from_millis(300));
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

        let (_port, _tx, _rx) = {
            let (msg_tx, msg_rx) = mpsc::channel::<PortMessage>();
            let port = VhostPort::new(
                &sock,
                "net0",
                PortSink {
                    tx: msg_tx.clone(),
                    rx: msg_rx,
                },
            )?;
            (port, msg_tx, msg_rx)
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
        let (sock, _port, _tx, _rx) = spawn_port(&root)?;

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
        let (msg_tx, msg_rx) = mpsc::channel::<PortMessage>();
        let result = VhostPort::new(
            "/proc/k8netd-test-nonexistent/nope.sock",
            "net0",
            PortSink { tx: msg_tx, rx: msg_rx },
        );
        assert!(result.is_err(), "missing parent dir must fail cleanly");
    }

    /// Edge: REQ-009 pins exactly one queue pair.
    #[test]
    fn edge_single_queue_pair_pinned() -> TestResult {
        let root = temp_root("edge-num-queues");
        fs::create_dir_all(&root)?;
        let (_sock, port, _tx, _rx) = spawn_port(&root)?;
        assert_eq!(port.num_queues(), 1);
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }
}
