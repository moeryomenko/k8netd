//! Fake vhost-user frontend for integration tests (TASK-018, part 1 of 2).
//!
//! Speaks the CLIENT side of the vhost-user protocol against a backend
//! listening on a Unix socket: performs the full handshake (SET_OWNER,
//! feature negotiation, protocol features, SET_MEM_TABLE backed by a
//! memfd region, and BOTH vrings of a virtio-net queue pair -- RX 0 / TX 1)
//! and exposes the negotiated state to tests through accessors. No frame
//! exchange logic here — that lives in the production port's tests (part 2).

// Test-only helper; accessors and constants are exercised by integration
// tests added in TASK-018 part 2.
#![allow(dead_code)]

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use vhost::vhost_user::message::{VhostUserHeaderFlag, VhostUserProtocolFeatures};
use vhost::vhost_user::{Frontend, VhostUserFrontend};
use vhost::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use vm_memory::{FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};
use vmm_sys_util::eventfd::EventFd;

/// Guest physical base of the single memory region.
pub const GUEST_BASE: u64 = 0x1000_0000;
/// Size of the shared memory region (1 MiB).
const REGION_SIZE: u64 = 0x10_0000;
/// Per-vring ring-area stride inside the region: vring `i`'s rings live at
/// `GUEST_BASE + i * VRING_STRIDE` (+ the offsets below).
pub const VRING_STRIDE: u64 = 0x4_0000;
/// Split-virtqueue descriptor table offset within a vring's area.
pub const DESC_TABLE_OFFSET: u64 = 0x0;
/// Used ring offset within a vring's area.
pub const USED_RING_OFFSET: u64 = 0x1_0000;
/// Available ring offset within a vring's area.
pub const AVAIL_RING_OFFSET: u64 = 0x2_0000;
/// Scratch area for frame buffers, past both vring areas.
pub const DATA_OFFSET: u64 = 0x8_0000;
/// Queue size negotiated for every vring.
pub const QUEUE_SIZE: u16 = 256;
/// VIRTIO_F_VERSION_1 feature bit (bit 32), mandatory for virtio 1.0+.
const VIRTIO_F_VERSION_1: u64 = 1 << 32;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct FakeFrontend {
    fe: Frontend,
    mem: GuestMemoryMmap<()>,
    kick: [EventFd; 2],
    call: [EventFd; 2],
    features: u64,
    protocol_features: VhostUserProtocolFeatures,
}

impl FakeFrontend {
    /// Connects to a vhost-user backend socket and runs the full
    /// client-side handshake for a complete virtio-net queue pair:
    /// SET_VRING_NUM/ADDR/KICK/CALL/ENABLE for vring 0 (RX) and vring 1 (TX).
    pub fn connect(socket_path: impl AsRef<Path>) -> Result<Self> {
        let mut fe = Frontend::connect(socket_path.as_ref(), u64::from(QUEUE_SIZE))?;
        // Make every request synchronous so handshake failures surface here.
        fe.set_hdr_flags(VhostUserHeaderFlag::NEED_REPLY);

        fe.set_owner()?;

        let backend_features = fe.get_features()?;
        let features = backend_features | VIRTIO_F_VERSION_1;
        fe.set_features(features)?;

        let advertised = fe.get_protocol_features()?;
        fe.set_protocol_features(advertised)?;

        let mem = Self::build_guest_memory()?;
        let userspace_addr = mem.get_host_address(GuestAddress(GUEST_BASE))? as u64;
        let mmap_handle = mem
            .find_region(GuestAddress(GUEST_BASE))
            .and_then(|region| region.file_offset())
            .map(|file_offset| file_offset.file().as_raw_fd())
            .ok_or("memory region has no backing file")?;

        fe.set_mem_table(&[VhostUserMemoryRegionInfo {
            guest_phys_addr: GUEST_BASE,
            memory_size: REGION_SIZE,
            userspace_addr,
            mmap_offset: 0,
            mmap_handle,
        }])?;

        let kick = [EventFd::new(libc::EFD_NONBLOCK)?, EventFd::new(libc::EFD_NONBLOCK)?];
        let call = [EventFd::new(libc::EFD_NONBLOCK)?, EventFd::new(libc::EFD_NONBLOCK)?];

        // The backend handler translates VMM virtual addresses to guest
        // physical ones via the SET_MEM_TABLE mapping, so the ring addresses
        // must be expressed in the mapping's address space (userspace base +
        // vring area), not as raw guest-physical values.
        for (i, (k, c)) in kick.iter().zip(call.iter()).enumerate() {
            let area = userspace_addr + u64::try_from(i).expect("vring index fits u64") * VRING_STRIDE;
            fe.set_vring_num(i, QUEUE_SIZE)?;
            fe.set_vring_addr(
                i,
                &VringConfigData {
                    queue_max_size: QUEUE_SIZE,
                    queue_size: QUEUE_SIZE,
                    flags: 0,
                    desc_table_addr: area + DESC_TABLE_OFFSET,
                    used_ring_addr: area + USED_RING_OFFSET,
                    avail_ring_addr: area + AVAIL_RING_OFFSET,
                    log_addr: None,
                },
            )?;
            fe.set_vring_kick(i, k)?;
            fe.set_vring_call(i, c)?;
            fe.set_vring_enable(i, true)?;
        }

        Ok(Self {
            fe,
            mem,
            kick,
            call,
            features,
            protocol_features: advertised,
        })
    }

    /// Creates a memfd-backed guest memory mapping with a single region.
    fn build_guest_memory() -> Result<GuestMemoryMmap<()>> {
        let file = create_memfd_region()?;
        file.set_len(REGION_SIZE)?;
        Ok(GuestMemoryMmap::<()>::from_ranges_with_files([(
            GuestAddress(GUEST_BASE),
            REGION_SIZE as usize,
            Some(FileOffset::new(file, 0)),
        )])?)
    }

    /// The guest memory handle backing the negotiated region.
    pub fn mem(&self) -> &GuestMemoryMmap<()> {
        &self.mem
    }

    /// Raw fd of vring `vring`'s kick eventfd (frontend -> backend doorbell).
    pub fn kick_fd(&self, vring: usize) -> RawFd {
        self.kick[vring].as_raw_fd()
    }

    /// Raw fd of vring `vring`'s call eventfd (backend -> frontend notification).
    pub fn call_fd(&self, vring: usize) -> RawFd {
        self.call[vring].as_raw_fd()
    }

    /// Feature bits sent during SET_FEATURES (backend bits | VERSION_1).
    pub fn features(&self) -> u64 {
        self.features
    }

    /// Protocol feature bits negotiated during SET_PROTOCOL_FEATURES.
    pub fn protocol_features(&self) -> VhostUserProtocolFeatures {
        self.protocol_features
    }

    /// Mutable access to the underlying frontend for frame-level tests.
    pub fn frontend_mut(&mut self) -> &mut Frontend {
        &mut self.fe
    }
}

/// Creates an anonymous memfd suitable for mmap-backed guest memory.
fn create_memfd_region() -> Result<File> {
    // SAFETY: `memfd_create` takes only a valid NUL-terminated `c""` literal
    // and flags; there are no preconditions beyond the syscall contract. The
    // returned raw fd is exclusively owned and wrapped immediately.
    let fd = unsafe { libc::memfd_create(c"k8netd-fake-frontend".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `fd` is a freshly created, owned memfd from `memfd_create`.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}
