//! Passt WAN subprocess manager (spec REQ-008, VC-08; plan TASK-022/023).
//!
//! One passt process per attached port — never shared (per-port isolation).
//! Frames cross the process boundary over an `AF_UNIX` socketpair whose
//! port-side end is handed to passt via `-F/--fd`; traffic is framed with a
//! 4-byte vnet header. The manager restarts a passt that exits on its own and
//! terminates it on detach.
//!
//! # argv contract (pinned by the integration spec)
//!
//! ```text
//! passt -F <fd> -a <vm-ip> -t <host-port>:<vm-ip>/<vm-port> ...
//! ```
//!
//! Unit tests stub the `passt` binary on PATH (a shell script that records
//! argv and exits on cue); no real passt is required.

use std::io;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::time::Duration;

/// Direction byte of the vnet header: VM -> wire (egress).
pub const VNET_EGRESS: u8 = 0x01;
/// Direction byte of the vnet header: wire -> VM (ingress).
pub const VNET_INGRESS: u8 = 0x02;
/// Vnet header size: 1 direction byte + 1 reserved + 2 big-endian length.
pub const VNET_HEADER_LEN: usize = 4;

/// One TCP port-forward rendered as `-t <host>:<vm-ip>/<vm>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortForward {
    /// Host-side TCP port.
    pub host: u16,
    /// VM-side TCP port.
    pub vm: u16,
}

/// Everything needed to spawn one passt for one attached port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasstConfig {
    /// VM address advertised with `-a`.
    pub vm_ip: String,
    /// Port forwards rendered as `-t` flags, in order.
    pub forwards: Vec<PortForward>,
}

/// Builds the exact passt argv for `config`, serving `fd`.
///
/// Pure function so tests can pin the argv without spawning anything.
pub fn passt_argv(config: &PasstConfig, fd: RawFd) -> Vec<String> {
    let mut argv = vec![
        "passt".to_string(),
        "--fd".to_string(),
        fd.to_string(),
        "-a".to_string(),
        config.vm_ip.clone(),
    ];
    for f in &config.forwards {
        argv.push(format!("-t{}:{}/{}", f.host, config.vm_ip, f.vm));
    }
    argv
}

/// Encodes `payload` (an Ethernet frame) into a vnet-header-framed buffer.
pub fn encode_vnet(direction: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut out = Vec::with_capacity(VNET_HEADER_LEN + payload.len());
    out.push(direction);
    out.push(0);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Decodes a vnet-header-framed buffer into `(direction, payload)`.
///
/// Errors when the buffer is shorter than the header or truncated against
/// the declared length.
pub fn decode_vnet(buf: &[u8]) -> Result<(u8, &[u8]), VnetError> {
    if buf.len() < VNET_HEADER_LEN {
        return Err(VnetError::TooShort(buf.len()));
    }
    let direction = buf[0];
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = VNET_HEADER_LEN.checked_add(len).ok_or(VnetError::TooShort(buf.len()))?;
    if buf.len() < end {
        return Err(VnetError::Truncated {
            declared: len as u16,
            have: buf.len() - VNET_HEADER_LEN,
        });
    }
    Ok((direction, &buf[VNET_HEADER_LEN..end]))
}

/// vnet framing decode failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VnetError {
    /// Buffer shorter than the 4-byte header.
    TooShort(usize),
    /// Declared payload length exceeds the bytes present.
    Truncated { declared: u16, have: usize },
}

impl std::fmt::Display for VnetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VnetError::TooShort(n) => write!(f, "vnet buffer too short: {n} bytes"),
            VnetError::Truncated { declared, have } => {
                write!(f, "vnet frame truncated: declared {declared}, have {have}")
            }
        }
    }
}

impl std::error::Error for VnetError {}

/// A live passt child plus its socketpair ends.
pub struct PasstProc {
    child: Child,
    /// Port side of the socketpair: k8netd reads/writes framed frames here.
    pub stream: UnixStream,
    /// The fd number passt was told to serve (`--fd`).
    pub served_fd: RawFd,
}

impl PasstProc {
    /// Creates an `AF_UNIX` SOCK_STREAM socketpair and returns both ends as
    /// raw fds `(k8netd_side, passt_side)`.
    fn socketpair() -> io::Result<(RawFd, RawFd)> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: plain fdw socketpair syscall; both fds are owned by us on
        // success and neither is closed on failure.
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }

    /// Spawns one passt for `config`, serving the passt side of a fresh
    /// socketpair. Returns the child plus the k8netd-side stream.
    pub fn spawn(config: &PasstConfig) -> io::Result<Self> {
        let (ours, theirs) = Self::socketpair()?;
        let argv = passt_argv(config, theirs);
        let stream = unsafe {
            // SAFETY: we own `ours` for the lifetime of the returned struct.
            UnixStream::from_raw_fd(ours)
        };
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        // The passt-side fd has no CLOEXEC flag, so it is inherited as-is.
        let child = cmd.spawn();
        // Parent must close its copy of the passt side either way.
        let result = match child {
            Ok(c) => Ok(PasstProc {
                child: c,
                stream,
                served_fd: theirs,
            }),
            Err(e) => Err(e),
        };
        unsafe {
            // SAFETY: `theirs` was either inherited via dup2 in the child or
            // is now orphaned; closing the parent copy is correct in both.
            libc::close(theirs);
        }
        result
    }

    /// The child's process id.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Whether the child has exited (non-blocking check).
    pub fn exited(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    /// Terminates the child: SIGTERM first, SIGKILL after `grace`.
    pub fn terminate(&mut self, grace: Duration) -> io::Result<()> {
        // SAFETY: signalling a child we own.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = std::time::Instant::now() + grace;
        loop {
            match self.child.try_wait()? {
                Some(_) => return Ok(()),
                None if std::time::Instant::now() >= deadline => break,
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        self.child.kill()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    static SEQ: AtomicU32 = AtomicU32::new(0);
    /// Serializes tests that swap the process-global PATH (env is not
    /// thread-local; parallel mutation races with sibling spawns).
    static PATH_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn temp_root(tag: &str) -> PathBuf {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("k8netd-passt-{tag}-{}-{n}", std::process::id()))
    }

    fn cfg(forwards: &[(u16, u16)]) -> PasstConfig {
        PasstConfig {
            vm_ip: "192.168.124.20".to_string(),
            forwards: forwards.iter().map(|&(h, v)| PortForward { host: h, vm: v }).collect(),
        }
    }

    /// REQ-008 / VC-08: the exact argv per attached port.
    #[test]
    fn argv_matches_contract_single_forward() -> TestResult {
        let argv = passt_argv(&cfg(&[(6443, 6443)]), 7);
        assert_eq!(
            argv,
            vec![
                "passt",
                "--fd",
                "7",
                "-a",
                "192.168.124.20",
                "-t6443:192.168.124.20/6443"
            ]
        );
        Ok(())
    }

    /// Multiple forwards render in order, one `-t` flag each.
    #[test]
    fn argv_multiple_forwards_in_order() -> TestResult {
        let argv = passt_argv(&cfg(&[(6443, 6443), (22, 2222)]), 9);
        assert_eq!(&argv[..5], &["passt", "--fd", "9", "-a", "192.168.124.20"]);
        assert_eq!(argv[5], "-t6443:192.168.124.20/6443");
        assert_eq!(argv[6], "-t22:192.168.124.20/2222");
        assert_eq!(argv.len(), 7);
        Ok(())
    }

    /// No forwards: argv has no `-t` flags at all.
    #[test]
    fn argv_without_forwards_has_no_t_flags() -> TestResult {
        let argv = passt_argv(&cfg(&[]), 3);
        assert_eq!(argv.len(), 5);
        assert!(argv.iter().all(|a| !a.starts_with("-t")));
        Ok(())
    }

    /// vnet framing round-trips egress and ingress payloads exactly.
    #[test]
    fn vnet_round_trip_both_directions() -> TestResult {
        let frame = make_frame(64);
        for dir in [VNET_EGRESS, VNET_INGRESS] {
            let encoded = encode_vnet(dir, &frame);
            assert_eq!(encoded.len(), VNET_HEADER_LEN + frame.len());
            let (d, payload) = decode_vnet(&encoded)?;
            assert_eq!(d, dir);
            assert_eq!(payload, &frame[..]);
        }
        Ok(())
    }

    /// Framing rejects short buffers and truncation against declared length.
    #[test]
    fn vnet_rejects_short_and_truncated() -> TestResult {
        assert_eq!(decode_vnet(&[0u8; 3]), Err(VnetError::TooShort(3)));
        // Declares 200 payload bytes but carries none.
        let bad = encode_vnet(VNET_INGRESS, &[]);
        let mut trunc = bad.clone();
        trunc[2] = 0;
        trunc[3] = 200;
        assert_eq!(
            decode_vnet(&trunc),
            Err(VnetError::Truncated { declared: 200, have: 0 })
        );
        Ok(())
    }

    /// Socketpair creation yields two valid, connected descriptors.
    #[test]
    fn socketpair_creates_connected_pair() -> TestResult {
        let (a, b) = PasstProc::socketpair()?;
        assert!(a >= 0 && b >= 0 && a != b);
        // SAFETY: test-local fds just created above.
        let sa = unsafe { UnixStream::from_raw_fd(a) };
        let sb = unsafe { UnixStream::from_raw_fd(b) };
        sa.set_nonblocking(true)?;
        sb.set_nonblocking(true)?;
        use std::io::Write;
        (&sa).write_all(b"x")?;
        let mut buf = [0u8; 1];
        use std::io::Read;
        (&sb).read_exact(&mut buf)?;
        assert_eq!(buf[0], b'x');
        Ok(())
    }

    /// Spawn against a stubbed passt binary: child starts, terminate stops it.
    #[test]
    fn spawn_stub_then_terminate_on_detach() -> TestResult {
        let root = temp_root("term");
        let _path_serialized = PATH_LOCK
            .lock()
            .map_err(|p| -> Box<dyn std::error::Error + Send + Sync> { p.to_string().into() })?;
        fs::create_dir_all(&root)?;
        let _guard = stub_passt_on_path(&root, "sleep 30")?;
        let mut proc = PasstProc::spawn(&cfg(&[(6443, 6443)]))?;
        assert!(!proc.exited(), "stub passt should still be running");
        proc.terminate(Duration::from_secs(2))?;
        assert!(proc.exited(), "terminate must stop the child");
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Restart-on-exit: after the stub exits itself, a fresh spawn succeeds
    /// (the manager-level restart is a re-spawn; proven here at unit level).
    #[test]
    fn respawn_after_exit_succeeds() -> TestResult {
        let root = temp_root("respawn");
        let _path_serialized = PATH_LOCK
            .lock()
            .map_err(|p| -> Box<dyn std::error::Error + Send + Sync> { p.to_string().into() })?;
        fs::create_dir_all(&root)?;
        let _guard = stub_passt_on_path(&root, "exit 0")?;
        let mut first = PasstProc::spawn(&cfg(&[]))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !first.exited() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(first.exited(), "stub must exit on its own");
        let _guard2 = stub_passt_on_path(&root, "sleep 30")?;
        let mut second = PasstProc::spawn(&cfg(&[]))?;
        assert!(!second.exited(), "respawned passt must be running");
        second.terminate(Duration::from_secs(2))?;
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    /// Per-port isolation: two spawns are two distinct children.
    #[test]
    fn two_ports_get_two_distinct_processes() -> TestResult {
        let root = temp_root("iso");
        let _path_serialized = PATH_LOCK
            .lock()
            .map_err(|p| -> Box<dyn std::error::Error + Send + Sync> { p.to_string().into() })?;
        fs::create_dir_all(&root)?;
        let _guard = stub_passt_on_path(&root, "sleep 30")?;
        let mut p1 = PasstProc::spawn(&cfg(&[(6443, 6443)]))?;
        let mut p2 = PasstProc::spawn(&cfg(&[(22, 22)]))?;
        assert_ne!(p1.child.id(), p2.child.id(), "one passt per port");
        assert_ne!(p1.stream.as_raw_fd(), p2.stream.as_raw_fd());
        p1.terminate(Duration::from_secs(2))?;
        p2.terminate(Duration::from_secs(2))?;
        let _ = fs::remove_dir_all(&root);
        Ok(())
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

    /// Installs a stub `passt` executable that runs `body` and prepends its
    /// directory to PATH for the duration of the test.
    fn stub_passt_on_path(
        root: &std::path::Path,
        body: &str,
    ) -> Result<PathGuard, Box<dyn std::error::Error + Send + Sync>> {
        // Caller must hold PATH_LOCK (env is process-global).
        let bin = root.join("bin");
        fs::create_dir_all(&bin)?;
        let script = bin.join("passt");
        fs::write(&script, format!("#!/bin/sh\n{}\n", body))?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))?;
        let old = std::env::var("PATH").unwrap_or_default();
        // SAFETY: single-threaded test process; PATH is restored on drop.
        unsafe { std::env::set_var("PATH", format!("{}:{}", bin.display(), old)) };
        Ok(PathGuard { old })
    }

    /// Restores PATH on drop so parallel tests do not leak the stub.
    struct PathGuard {
        old: String,
    }

    impl Drop for PathGuard {
        fn drop(&mut self) {
            // SAFETY: restoring the saved value captured at stub install time.
            unsafe { std::env::set_var("PATH", &self.old) };
        }
    }
}
