//! Persisted state store for the k8netd daemon.
//!
//! State lives in the socket directory (spec REQ-010) and is written atomically
//! (temp file + rename) so that a crash never leaves a partially-written state
//! file. On startup the store restores networks, ports, attachments, IPAM records,
//! and DHCP leases so that a restarted frontend sees a consistent view.
//!
//! The state format is a JSON document with the following top-level keys:
//! - `networks`: map of network_name → network config
//! - `ports`: map of port_name → port config (attached VM, IPAM state)
//! - `ipam_records`: map of chaddr → Ipv4Cidr allocation
//! - `dhcp_leases`: map of chaddr → DhcpLease struct
//! - `version`: state format version (bumped on structural changes)

// use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Version of the state format. Increment on structural changes; on startup,
/// if the stored version is older than the current version, the store refuses
/// to load and the daemon starts with empty state.
const STATE_FORMAT_VERSION: &str = "1";

/// Path to the state file, relative to the socket directory.
const STATE_FILE_NAME: &str = "state.json";

/// Error type for state store operations.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("missing parent directory for {path:?}")]
    MissingParent { path: std::path::PathBuf },
    #[error("io error: {source}")]
    Io {
        source: std::io::Error,
        path: std::path::PathBuf,
    },
    #[error("invalid state format version: expected {expected}, found {found}")]
    VersionMismatch { expected: u32, found: u32 },
    #[error("corrupt state file: {source}")]
    Corrupt { source: serde_json::Error },
    #[error("state file not found: {path:?}")]
    NotFound { path: std::path::PathBuf },
}

/// Persisted state snapshot captured at a single point in time.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct StateSnapshot {
    /// Format version — bump on structural changes.
    version: u32,
    /// Maps network name → config (cidr, gateway, dns, mtu).
    pub networks: BTreeMap<String, NetworkState>,
    /// Maps port name → config (attached VM IP, MAC, IPAM state).
    pub ports: BTreeMap<String, PortState>,
    /// Maps client MAC (hex string) → allocated IPv4 CIDR.
    pub ipam_records: BTreeMap<String, String>,
    /// Maps client MAC (hex string) → DHCP lease struct.
    pub dhcp_leases: BTreeMap<String, DhcpLeaseState>,
}

/// Per-network persisted state.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct NetworkState {
    /// IPv4 CIDR for the network (e.g. "192.168.124.0/24").
    pub cidr: String,
    /// Gateway IP octets (last 3 octets; MAC is 02:00:<ip-octets>).
    pub gateway: String,
    /// DNS server(s) as configured.
    pub dns: Vec<String>,
    /// MTU override (default 1500).
    pub mtu: u16,
}

/// Per-port persisted state.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PortState {
    /// Attached VM's IP address (if any).
    pub vm_ip: Option<String>,
    /// VM's MAC address as hex string (e.g. "02:00:0a0a0a").
    pub mac: Option<String>,
    /// IPAM allocation state for this port.
    pub ipam: IpamSnapshot,
}

/// IPAM snapshot for a single port.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct IpamSnapshot {
    /// Free CIDR ranges not yet allocated.
    pub free_ranges: Vec<String>,
    /// Allocated leases: chaddr → IPv4.
    pub allocations: BTreeMap<String, String>,
}

/// DHCP lease state for a single client.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DhcpLeaseState {
    /// Chaddr as hex string (without colons, lower-case).
    pub chaddr: String,
    /// IA_NA IPv4 address.
    pub ip_address: String,
    /// Lease time in seconds.
    pub lease_time: u32,
    /// DNS server(s) supplied in the ACK.
    pub dns: Vec<String>,
}

/// Mutable in-memory state store exported by this module.
#[derive(Debug, Default)]
pub struct StateStore {
    /// Maps network name → persisted state.
    pub networks: BTreeMap<String, NetworkState>,
    /// Maps port name → persisted state.
    pub ports: BTreeMap<String, PortState>,
    /// Maps chaddr (hex, no colons) → allocated IPv4 CIDR.
    pub ipam_records: BTreeMap<String, String>,
    /// Maps chaddr (hex, no colons) → DHCP lease struct.
    pub dhcp_leases: BTreeMap<String, DhcpLeaseState>,
}

/// Deserialize a StateSnapshot from a JSON string slice.
pub fn parse_snapshot(data: &str) -> Result<StateSnapshot, StateError> {
    serde_json::from_str(data).map_err(|e| StateError::Corrupt {
        source: e,
        path: std::path::PathBuf::from("inline"),
    })
}

/// Serialize a StateSnapshot into a JSON string.
pub fn serialize_snapshot(snapshot: &StateSnapshot) -> Result<String, StateError> {
    serde_json::to_string(snapshot).map_err(|e| StateError::Io {
        source: std::io::Error::new(std::io::ErrorKind::Other, e),
        path: std::path::PathBuf::from("inline"),
    })
}

/// Load state from the socket directory, replacing the in-memory store.
/// Returns `Err` if the file is missing or corrupt.
pub fn load_from_disk(path: &Path) -> Result<StateStore, StateError> {
    let state_path = path.join(STATE_FILE_NAME);
    if !state_path.exists() {
        return Ok(StateStore::default());
    }
    let content = fs::read_to_string(&state_path).map_err(|e| StateError::Io {
        source: e,
        path: state_path,
    })?;
    let snapshot: StateSnapshot = serde_json::from_str(&content).map_err(|e| StateError::Corrupt {
        source: e,
        path: state_path,
    })?;
    // Validate version
    if snapshot.version != STATE_FORMAT_VERSION {
        return Err(StateError::VersionMismatch {
            expected: STATE_FORMAT_VERSION as u32,
            found: snapshot.version as u32,
        });
    }
    Ok(snapshot.into())
}

/// Persist the current state to disk atomically (temp file + rename).
/// REQ-010: the rename is atomic on POSIX filesystems; if the process
/// crashes before the rename, the original state file is never corrupted.
pub fn save_to_disk(store: &StateStore, path: &Path) -> Result<(), StateError> {
    let state_path = path.join(STATE_FILE_NAME);
    // Write to a temp file in the same directory first.
    let tmp_path = path.join(".state.json.tmp");
    let content = serde_json::to_string(store).map_err(|e| StateError::Io {
        source: std::io::Error::new(std::io::ErrorKind::Other, e),
        path: tmp_path,
    })?;
    fs::write(&tmp_path, content).map_err(|e| StateError::Io {
        source: e,
        path: tmp_path,
    })?;
    // Atomic rename — if the process crashes before this line, the
    // original state file is untouched.
    fs::rename(&tmp_path, &state_path).map_err(|e| StateError::Io {
        source: e,
        path: state_path,
    })?;
    Ok(())
}

/// Insert a network state entry into the store.
pub fn insert_network(store: &mut StateStore, name: String, state: NetworkState) {
    store.networks.insert(name, state);
}

/// Remove a network state entry from the store.
pub fn remove_network(store: &mut StateStore, name: &str) -> Option<NetworkState> {
    store.networks.remove(name)
}

/// Get a network state by name.
pub fn get_network(store: &StateStore, name: &str) -> Option<&NetworkState> {
    store.networks.get(name)
}

/// Insert a port state entry into the store.
pub fn insert_port(store: &mut StateStore, name: String, state: PortState) {
    store.ports.insert(name, state);
}

/// Remove a port state entry from the store.
pub fn remove_port(store: &mut StateStore, name: &str) -> Option<PortState> {
    store.ports.remove(name)
}

/// Get a port state by name.
pub fn get_port(store: &StateStore, name: &str) -> Option<&PortState> {
    store.ports.get(name)
}

/// Insert an IPAM record (chaddr → CIDR).
pub fn insert_ipam(store: &mut StateStore, chaddr: String, cidr: String) {
    store.ipam_records.insert(chaddr, cidr);
}

/// Remove an IPAM record.
pub fn remove_ipam(store: &mut StateStore, chaddr: &str) -> Option<String> {
    store.ipam_records.remove(chaddr)
}

/// Get an IPAM record.
pub fn get_ipam(store: &StateStore, chaddr: &str) -> Option<&String> {
    store.ipam_records.get(chaddr)
}

/// Insert a DHCP lease state entry.
pub fn insert_dhcp_lease(store: &mut StateStore, chaddr: String, lease: DhcpLeaseState) {
    store.dhcp_leases.insert(chaddr, lease);
}

/// Remove a DHCP lease state entry.
pub fn remove_dhcp_lease(store: &mut StateStore, chaddr: &str) -> Option<DhcpLeaseState> {
    store.dhcp_leases.remove(chaddr)
}

/// Get a DHCP lease state entry.
pub fn get_dhcp_lease(store: &StateStore, chaddr: &str) -> Option<&DhcpLeaseState> {
    store.dhcp_leases.get(chaddr)
}

/// Number of stored networks.
pub fn network_count(store: &StateStore) -> usize {
    store.networks.len()
}

/// Number of stored ports.
pub fn port_count(store: &StateStore) -> usize {
    store.ports.len()
}

/// Number of stored IPAM records.
pub fn ipam_count(store: &StateStore) -> usize {
    store.ipam_records.len()
}

/// Number of stored DHCP leases.
pub fn dhcp_lease_count(store: &StateStore) -> usize {
    store.dhcp_leases.len()
}

// RED PHASE: the following functions are stubs that will be wired into
// the daemon's control-plane handler (TASK-025) and the restart path
// (TASK-021). They are not expected to compile until the daemon main binary
// integrates them, but the types and API surface must be present here so
// that TASK-020 tests can reference them.

// /// Load state from the socket directory, replacing the in-memory store.
// // pub fn load_state_from_socket_dir(socket_dir: &Path) -> Result<StateStore, StateError> {
// //     let state_path = socket_dir.join(STATE_FILE_NAME);
// //     StateStore::load_from_disk(&state_path)
// // }
//
// /// Persist the current state to the socket directory atomically.
// pub fn save_state_to_socket_dir(store: &StateStore, socket_dir: &Path) -> Result<(), StateError> {
// //     StateStore::save_to_disk(store, socket_dir.join(STATE_FILE_NAME))
// // }
//
// /// Convenience: save then immediately re-load, returning the loaded store.
// pub fn refresh_state(socket_dir: &Path) -> Result<StateStore, StateError> {
// //     let store = StateStore::new(); // would be constructed from running daemon state
// //     StateStore::save_to_disk(&store, socket_dir.join(STATE_FILE_NAME))?;
// //     StateStore::load_from_disk(socket_dir.join(STATE_FILE_NAME))
// // }
