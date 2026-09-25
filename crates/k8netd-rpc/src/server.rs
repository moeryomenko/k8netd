//! Control-plane server: JSON-RPC method routing and the in-memory control
//! plane (spec REQ-001..REQ-004; plan TASK-024/025).
//!
//! The [`Router`] is transport-agnostic: it turns a parsed [`Request`] into a
//! [`Response`] by calling the [`ControlPlane`] trait. [`MemoryControlPlane`]
//! is the reference implementation backed by `k8netd-core` domain types —
//! idempotent `Create*`, typed errors, IPAM reservations. The daemon binary
//! (TASK-031) swaps in the full implementation wired to vhost ports and passt.
//!
//! Wire framing: newline-delimited JSON over the AF_UNIX control socket, one
//! connection at a time (plan assumption 2).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixListener;
use std::path::Path;

use k8netd_core::ipam::{Ipam, IpamError};
use k8netd_core::model::{IpPool, MacAddr, Network, Port, PublishTable};
use serde_json::{Value, json};

use crate::protocol::{Request, Response, RpcError};

/// Default inclusive host-port range for the PublishPort allocator
/// (REQ-010); chosen below the typical Linux ephemeral port range.
pub const DEFAULT_PUBLISH_RANGE: (u16, u16) = (20_000, 21_000);

/// The control-plane operations exposed over the control socket.
///
/// Each method maps 1:1 to a JSON-RPC method name; params extraction and
/// error mapping live in the [`Router`].
pub trait ControlPlane {
    fn create_network(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn delete_network(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn get_network(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn create_port(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn delete_port(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn get_port(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn attach_port(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn detach_port(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn allocate_ip(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn release_ip(&mut self, params: &Value) -> Result<Value, RpcError>;
    /// Publishes an inbound forward for `(port, vm_port)` and returns the
    /// allocated host port (REQ-010). Idempotent per pair; errors for
    /// unknown or unattached ports; exhaustion surfaces as `conflict`.
    fn publish_port(&mut self, params: &Value) -> Result<Value, RpcError>;
    fn unpublish_port(&mut self, params: &Value) -> Result<Value, RpcError>;
}

/// Routes parsed requests to a [`ControlPlane`], mapping domain failures to
/// typed RPC errors (REQ-001).
pub struct Router<C: ControlPlane> {
    cp: C,
}

impl<C: ControlPlane> Router<C> {
    pub fn new(cp: C) -> Self {
        Router { cp }
    }

    /// Dispatches one request; never panics — every failure becomes an error
    /// response carrying the request id.
    pub fn dispatch(&mut self, req: Request) -> Response {
        let result = match req.method.as_str() {
            "CreateNetwork" => self.cp.create_network(req.params.as_ref().unwrap_or(&Value::Null)),
            "DeleteNetwork" => self.cp.delete_network(req.params.as_ref().unwrap_or(&Value::Null)),
            "GetNetwork" => self.cp.get_network(req.params.as_ref().unwrap_or(&Value::Null)),
            "CreatePort" => self.cp.create_port(req.params.as_ref().unwrap_or(&Value::Null)),
            "DeletePort" => self.cp.delete_port(req.params.as_ref().unwrap_or(&Value::Null)),
            "GetPort" => self.cp.get_port(req.params.as_ref().unwrap_or(&Value::Null)),
            "AttachPort" => self.cp.attach_port(req.params.as_ref().unwrap_or(&Value::Null)),
            "DetachPort" => self.cp.detach_port(req.params.as_ref().unwrap_or(&Value::Null)),
            "AllocateIP" => self.cp.allocate_ip(req.params.as_ref().unwrap_or(&Value::Null)),
            "ReleaseIP" => self.cp.release_ip(req.params.as_ref().unwrap_or(&Value::Null)),
            "PublishPort" => self.cp.publish_port(req.params.as_ref().unwrap_or(&Value::Null)),
            "UnpublishPort" => self.cp.unpublish_port(req.params.as_ref().unwrap_or(&Value::Null)),
            _ => Err(RpcError::MethodNotFound),
        };
        match result {
            Ok(v) => Response::ok(req.id, v),
            Err(e) => Response::err(req.id, e),
        }
    }

    /// Mutable access for tests and the daemon runtime.
    pub fn control_plane(&mut self) -> &mut C {
        &mut self.cp
    }
}

// ---------------------------------------------------------------------------
// Param helpers
// ---------------------------------------------------------------------------

fn str_param<'a>(params: &'a Value, key: &str) -> Result<&'a str, RpcError> {
    params.get(key).and_then(Value::as_str).ok_or(RpcError::InvalidParams)
}

/// Extracts a `u16` parameter, rejecting values outside the u16 domain.
fn u16_param(params: &Value, key: &str) -> Result<u16, RpcError> {
    params
        .get(key)
        .and_then(Value::as_u64)
        .filter(|v| *v <= u64::from(u16::MAX))
        .map(|v| v as u16)
        .ok_or(RpcError::InvalidParams)
}

fn ipam_error(e: IpamError) -> RpcError {
    match e {
        IpamError::PoolExhausted => RpcError::Conflict,
        _ => RpcError::Internal,
    }
}

// ---------------------------------------------------------------------------
// In-memory reference control plane
// ---------------------------------------------------------------------------

/// A network as created: the domain object plus its creation params, kept so
/// idempotent re-creates can compare parameters exactly (REQ-001).
struct NetworkEntry {
    network: Network,
    ipam: Ipam,
    created_with: Value,
}

/// In-memory [`ControlPlane`] over `k8netd-core` types. Port sockets are
/// modelled by path only here; the real socket lifecycle is wired in TASK-031.
pub struct MemoryControlPlane {
    networks: BTreeMap<String, NetworkEntry>,
    ports: BTreeMap<String, Port>,
    /// Inclusive host-port range the publish allocator hands out (REQ-010).
    publish_range: (u16, u16),
    /// Published inbound-forward allocations keyed by port name.
    publish_table: PublishTable,
}

impl Default for MemoryControlPlane {
    fn default() -> Self {
        MemoryControlPlane {
            networks: BTreeMap::new(),
            ports: BTreeMap::new(),
            publish_range: DEFAULT_PUBLISH_RANGE,
            publish_table: PublishTable::default(),
        }
    }
}

impl MemoryControlPlane {
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a control plane whose publish allocator hands out host ports
    /// from the inclusive range `[start, end]` (REQ-010 exhaustion probes).
    pub fn with_publish_range(start: u16, end: u16) -> Self {
        Self {
            publish_range: (start, end),
            ..Self::default()
        }
    }

    /// Restores a control plane from a persisted state store, seeding the
    /// publish allocator so re-publishes honor pre-restart allocations
    /// (REQ-010 / VC-06 restart path).
    pub fn from_store(store: k8netd_core::state::StateStore) -> Self {
        Self {
            publish_table: store.publish_table,
            ..Self::default()
        }
    }
}

impl ControlPlane for MemoryControlPlane {
    fn create_network(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_param(params, "name")?.to_string();
        let cidr = str_param(params, "cidr")?;
        let gateway = str_param(params, "gateway")?;
        let pool_start = str_param(params, "poolStart")?;
        let pool_end = str_param(params, "poolEnd")?;

        if let Some(entry) = self.networks.get(&name) {
            // REQ-001: idempotent when identical, conflict otherwise.
            return if entry.created_with == *params {
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
        let network = Network::new(&name, cidr, gateway, pool).map_err(|_| RpcError::InvalidParams)?;
        let ipam = Ipam::new(network.clone());
        self.networks.insert(
            name,
            NetworkEntry {
                network,
                ipam,
                created_with: params.clone(),
            },
        );
        Ok(Value::Null)
    }

    fn delete_network(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_param(params, "name")?;
        self.networks
            .remove(name)
            .map(|_| Value::Null)
            .ok_or(RpcError::NotFound)
    }

    fn get_network(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_param(params, "name")?;
        let e = self.networks.get(name).ok_or(RpcError::NotFound)?;
        Ok(json!({
            "name": e.network.name,
            "cidr": e.network.cidr.to_string(),
            "gateway": e.network.gateway.to_string(),
        }))
    }

    fn create_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_param(params, "name")?.to_string();
        if self.ports.contains_key(&name) {
            // Socket path derives from the name, so re-create is always
            // identical: plain idempotent success (REQ-001/REQ-003).
            return Ok(Value::Null);
        }
        let port =
            Port::new(&name, format!("/run/user/1000/k8snet/{name}.sock")).map_err(|_| RpcError::InvalidParams)?;
        self.ports.insert(name, port);
        Ok(Value::Null)
    }

    fn delete_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_param(params, "name")?;
        // REQ-010: deleting the owning port frees its published allocations.
        self.publish_table.remove_port(name);
        self.ports.remove(name).map(|_| Value::Null).ok_or(RpcError::NotFound)
    }

    fn get_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_param(params, "name")?;
        let p = self.ports.get(name).ok_or(RpcError::NotFound)?;
        Ok(json!({
            "name": p.name,
            "network": p.network,
            "mac": p.mac.map(|m| m.to_string()),
            "ip": p.ip.map(|i| i.to_string()),
        }))
    }

    fn attach_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let port_name = str_param(params, "port")?.to_string();
        let net_name = str_param(params, "network")?.to_string();
        let mac: MacAddr = str_param(params, "mac")?.parse().map_err(|_| RpcError::InvalidParams)?;

        if !self.ports.contains_key(&port_name) {
            return Err(RpcError::NotFound);
        }
        let ip = {
            let entry = self.networks.get_mut(&net_name).ok_or(RpcError::NotFound)?;
            // REQ-004: attach reserves the IP before the VM boots.
            entry.ipam.allocate(mac).map_err(ipam_error)?
        };
        let port = self.ports.get_mut(&port_name).expect("checked above");
        if port.network.as_deref() == Some(net_name.as_str()) && port.mac == Some(mac) {
            return Ok(Value::Null); // idempotent re-attach
        }
        if port.network.is_some() {
            return Err(RpcError::Conflict); // attached elsewhere
        }
        port.attach(&net_name, mac, ip);
        Ok(Value::Null)
    }

    fn detach_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let name = str_param(params, "name")?;
        let port = self.ports.get_mut(name).ok_or(RpcError::NotFound)?;
        // Detaching an already-detached port is a no-op success; the socket
        // stays alive either way (REQ-003).
        port.detach();
        // REQ-010: detaching the owning port frees its published allocations.
        self.publish_table.remove_port(name);
        Ok(Value::Null)
    }

    fn allocate_ip(&mut self, params: &Value) -> Result<Value, RpcError> {
        let net = str_param(params, "network")?;
        let mac: MacAddr = str_param(params, "mac")?.parse().map_err(|_| RpcError::InvalidParams)?;
        let entry = self.networks.get_mut(net).ok_or(RpcError::NotFound)?;
        let ip = entry.ipam.allocate(mac).map_err(ipam_error)?;
        // Contract: AllocateIP's result is a bare JSON string carrying the
        // address, not an object.
        Ok(Value::String(ip.to_string()))
    }

    fn release_ip(&mut self, params: &Value) -> Result<Value, RpcError> {
        let net = str_param(params, "network")?;
        let mac: MacAddr = str_param(params, "mac")?.parse().map_err(|_| RpcError::InvalidParams)?;
        let entry = self.networks.get_mut(net).ok_or(RpcError::NotFound)?;
        entry.ipam.release(mac).map_err(|e| match e {
            IpamError::UnknownMac => RpcError::NotFound,
            other => ipam_error(other),
        })?;
        Ok(Value::Null)
    }

    fn publish_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let port_name = str_param(params, "port")?;
        let vm_port = u16_param(params, "vm_port")?;

        // REQ-010: only attached ports are publishable; unknown and
        // unattached (including since-detached) ports are not_found.
        let port = self.ports.get(port_name).ok_or(RpcError::NotFound)?;
        if port.network.is_none() {
            return Err(RpcError::NotFound);
        }

        // Idempotent re-publish returns the recorded allocation unchanged.
        let host_port = match self.publish_table.get(port_name, vm_port) {
            Some(host) => host,
            None => self
                .publish_table
                .allocate(port_name, vm_port, self.publish_range)
                .ok_or(RpcError::Conflict)?, // range exhaustion; no partial state
        };
        Ok(json!({ "host_port": host_port }))
    }

    fn unpublish_port(&mut self, params: &Value) -> Result<Value, RpcError> {
        let port_name = str_param(params, "port")?;
        let vm_port = u16_param(params, "vm_port")?;
        self.publish_table
            .remove(port_name, vm_port)
            .ok_or(RpcError::NotFound)?;
        Ok(Value::Null)
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Serves newline-delimited JSON-RPC on `path`, one connection at a time.
///
/// Blocks forever; intended for the daemon's dedicated thread.
pub fn serve<C: ControlPlane + Send + 'static>(path: &Path, mut router: Router<C>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(path); // stale socket unlink (REQ-010 pattern)
    let listener = UnixListener::bind(path)?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        if handle_connection(&mut stream, &mut router).is_err() {
            continue; // malformed client must not wedge the accept loop
        }
    }
    Ok(())
}

/// Reads one newline-framed request from `stream` and writes one response.
///
/// Returns the number of requests handled (0 on clean EOF, 1 otherwise).
pub fn handle_connection<C: ControlPlane, S: std::io::Read + std::io::Write>(
    stream: &mut S,
    router: &mut Router<C>,
) -> std::io::Result<usize> {
    let mut line = String::new();
    let n = {
        // Split borrows: read through a scoped BufReader, then write via the
        // original stream reference.
        let read_half: &mut dyn std::io::Read = stream;
        let mut reader = BufReader::new(read_half);
        reader.read_line(&mut line)?
    };
    if n == 0 {
        return Ok(0); // peer closed without sending
    }
    let response = match Request::parse(line.trim_end()) {
        Ok(req) => router.dispatch(req),
        Err(e) => Response::err(Value::Null, e),
    };
    let mut body = serde_json::to_string(&response).map_err(std::io::Error::other)?;
    body.push('\n');
    stream.write_all(body.as_bytes())?;
    stream.flush()?;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write as _;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn router() -> Router<MemoryControlPlane> {
        Router::new(MemoryControlPlane::new())
    }

    fn net_params(cidr: &str) -> Value {
        json!({
            "name": "net0",
            "cidr": cidr,
            "gateway": "192.168.124.1",
            "poolStart": "192.168.124.100",
            "poolEnd": "192.168.124.200",
        })
    }

    fn create_net(r: &mut Router<MemoryControlPlane>, cidr: &str) -> Response {
        r.dispatch(Request::new("CreateNetwork", Some(net_params(cidr)), json!(1)))
    }

    /// Unknown methods map to the typed method_not_found error.
    #[test]
    fn unknown_method_is_method_not_found() -> TestResult {
        let mut r = router();
        let resp = r.dispatch(Request::new("Nope", None, json!(7)));
        assert_eq!(resp.error.map(|e| e.code()), Some("method_not_found"));
        assert_eq!(resp.id, json!(7));
        Ok(())
    }

    /// Missing required params yield invalid_params, not a panic.
    #[test]
    fn missing_params_is_invalid_params() -> TestResult {
        let mut r = router();
        let resp = r.dispatch(Request::new("CreateNetwork", Some(json!({"name": "x"})), json!(1)));
        assert_eq!(resp.error.map(|e| e.code()), Some("invalid_params"));
        Ok(())
    }

    /// CreateNetwork: ok, then idempotent no-op, then conflict on change.
    #[test]
    fn create_network_idempotency_semantics() -> TestResult {
        let mut r = router();
        assert!(create_net(&mut r, "192.168.124.0/24").error.is_none());
        // Identical params: no-op success (REQ-001).
        assert!(create_net(&mut r, "192.168.124.0/24").error.is_none());
        // Different params: conflict.
        let resp = create_net(&mut r, "10.0.0.0/24");
        assert_eq!(resp.error.map(|e| e.code()), Some("conflict"));
        Ok(())
    }

    /// GetNetwork returns the stored geometry; missing names are not_found.
    #[test]
    fn get_network_round_trip_and_not_found() -> TestResult {
        let mut r = router();
        create_net(&mut r, "192.168.124.0/24");
        let resp = r.dispatch(Request::new("GetNetwork", Some(json!({"name": "net0"})), json!(2)));
        assert_eq!(resp.result.unwrap()["cidr"], "192.168.124.0/24");
        let resp = r.dispatch(Request::new("GetNetwork", Some(json!({"name": "zz"})), json!(3)));
        assert_eq!(resp.error.map(|e| e.code()), Some("not_found"));
        Ok(())
    }

    /// DeleteNetwork removes; deleting again is not_found.
    #[test]
    fn delete_network_lifecycle() -> TestResult {
        let mut r = router();
        create_net(&mut r, "192.168.124.0/24");
        let del = || Request::new("DeleteNetwork", Some(json!({"name": "net0"})), json!(4));
        assert!(r.dispatch(del()).error.is_none());
        assert_eq!(r.dispatch(del()).error.map(|e| e.code()), Some("not_found"));
        Ok(())
    }

    /// TASK-026: param comparison is exact serde Value equality — key order
    /// in the JSON object must not matter.
    #[test]
    fn create_network_key_order_insensitive_equality() -> TestResult {
        let mut r = router();
        let a = json!({"name": "n", "cidr": "10.0.0.0/24", "gateway": "10.0.0.1",
                       "poolStart": "10.0.0.10", "poolEnd": "10.0.0.20"});
        let b = json!({"poolEnd": "10.0.0.20", "poolStart": "10.0.0.10",
                           "gateway": "10.0.0.1", "cidr": "10.0.0.0/24", "name": "n"});
        assert_eq!(a, b, "serde Value equality ignores object key order");
        assert!(
            r.dispatch(Request::new("CreateNetwork", Some(a), json!(1)))
                .error
                .is_none()
        );
        assert!(
            r.dispatch(Request::new("CreateNetwork", Some(b), json!(2)))
                .error
                .is_none()
        );
        Ok(())
    }

    /// TASK-026: a deleted port can be freshly created again under the same
    /// name (delete truly destroys; create does not resurrect stale state).
    #[test]
    fn port_recreate_after_delete_is_fresh() -> TestResult {
        let mut r = router();
        r.dispatch(Request::new("CreatePort", Some(json!({"name": "p"})), json!(1)));
        r.dispatch(Request::new("DeletePort", Some(json!({"name": "p"})), json!(2)));
        assert!(
            r.dispatch(Request::new("CreatePort", Some(json!({"name": "p"})), json!(3)))
                .error
                .is_none()
        );
        let got = r.dispatch(Request::new("GetPort", Some(json!({"name": "p"})), json!(4)));
        let port = got.result.unwrap();
        assert_eq!(port["network"], Value::Null, "fresh port starts detached");
        Ok(())
    }

    /// CreatePort is idempotent (socket path derives from the name).
    #[test]
    fn create_port_idempotent_delete_not_found() -> TestResult {
        let mut r = router();
        let mk = Request::new("CreatePort", Some(json!({"name": "vm-a"})), json!(5));
        assert!(r.dispatch(mk.clone()).error.is_none());
        assert!(r.dispatch(mk).error.is_none());
        let del = Request::new("DeletePort", Some(json!({"name": "vm-a"})), json!(6));
        assert!(r.dispatch(del.clone()).error.is_none());
        assert_eq!(r.dispatch(del).error.map(|e| e.code()), Some("not_found"));
        Ok(())
    }

    /// AttachPort: not_found for missing objects, idempotent same-target
    /// attach, conflict on second network, detach leaves socket alive.
    #[test]
    fn attach_detach_transitions() -> TestResult {
        let mut r = router();
        create_net(&mut r, "192.168.124.0/24");
        r.dispatch(Request::new("CreatePort", Some(json!({"name": "p1"})), json!(1)));

        let attach = |r: &mut Router<MemoryControlPlane>| {
            r.dispatch(Request::new(
                "AttachPort",
                Some(json!({"port": "p1", "network": "net0", "mac": "02:00:00:00:00:01"})),
                json!(2),
            ))
        };
        assert!(attach(&mut r).error.is_none());
        assert!(attach(&mut r).error.is_none(), "re-attach is idempotent");

        // Second network, same port: conflict.
        r.dispatch(Request::new(
            "CreateNetwork",
            Some(json!({
                "name": "net1", "cidr": "10.0.0.0/24", "gateway": "10.0.0.1",
                "poolStart": "10.0.0.10", "poolEnd": "10.0.0.20"
            })),
            json!(3),
        ));
        let resp = r.dispatch(Request::new(
            "AttachPort",
            Some(json!({"port": "p1", "network": "net1", "mac": "02:00:00:00:00:01"})),
            json!(4),
        ));
        assert_eq!(resp.error.map(|e| e.code()), Some("conflict"));

        // Missing port / network are not_found.
        let resp = r.dispatch(Request::new(
            "AttachPort",
            Some(json!({"port": "ghost", "network": "net0", "mac": "02:00:00:00:00:09"})),
            json!(5),
        ));
        assert_eq!(resp.error.map(|e| e.code()), Some("not_found"));

        // Detach keeps the port queryable with empty bindings.
        assert!(
            r.dispatch(Request::new("DetachPort", Some(json!({"name": "p1"})), json!(6)))
                .error
                .is_none()
        );
        let got = r.dispatch(Request::new("GetPort", Some(json!({"name": "p1"})), json!(7)));
        let port = got.result.unwrap();
        assert_eq!(port["network"], Value::Null);
        assert_eq!(port["name"], "p1");
        Ok(())
    }

    /// AllocateIP hands out distinct pool IPs per MAC and honors reservations;
    /// ReleaseIP frees and reports not_found for unknown MACs.
    #[test]
    fn allocate_release_ip_semantics() -> TestResult {
        let mut r = router();
        create_net(&mut r, "192.168.124.0/24");
        let alloc = |r: &mut Router<MemoryControlPlane>, mac: &str| {
            r.dispatch(Request::new(
                "AllocateIP",
                Some(json!({"network": "net0", "mac": mac})),
                json!(1),
            ))
        };
        // Contract: the result is a bare JSON string carrying the address.
        let ip1 = alloc(&mut r, "02:00:00:00:00:01")
            .result
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let ip2 = alloc(&mut r, "02:00:00:00:00:02")
            .result
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(ip1, ip2, "distinct MACs get distinct IPs");
        // Reservation is stable across repeated allocations (REQ-004).
        let again = alloc(&mut r, "02:00:00:00:00:01")
            .result
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(again, ip1);

        let rel = |r: &mut Router<MemoryControlPlane>, mac: &str| {
            r.dispatch(Request::new(
                "ReleaseIP",
                Some(json!({"network": "net0", "mac": mac})),
                json!(2),
            ))
        };
        assert!(rel(&mut r, "02:00:00:00:00:01").error.is_none());
        assert_eq!(
            rel(&mut r, "02:00:00:00:00:01").error.map(|e| e.code()),
            Some("not_found")
        );
        // Allocation on a missing network is not_found.
        let resp = r.dispatch(Request::new(
            "AllocateIP",
            Some(json!({"network": "zz", "mac": "02:00:00:00:00:01"})),
            json!(3),
        ));
        assert_eq!(resp.error.map(|e| e.code()), Some("not_found"));
        Ok(())
    }

    /// handle_connection round-trips one framed request over a socketpair.
    #[test]
    fn connection_round_trip_over_socketpair() -> TestResult {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair()?;
        let mut r = router();
        create_net(&mut r, "192.168.124.0/24");

        let req = Request::new("GetNetwork", Some(json!({"name": "net0"})), json!("abc"));
        writeln!(a, "{}", serde_json::to_string(&req)?)?;
        a.flush()?;
        assert_eq!(handle_connection(&mut b, &mut r)?, 1);

        let mut line = String::new();
        BufReader::new(&mut a).read_line(&mut line)?;
        let resp: Response = serde_json::from_str(line.trim())?;
        assert_eq!(resp.id, json!("abc"));
        assert_eq!(resp.result.unwrap()["gateway"], "192.168.124.1");
        Ok(())
    }

    /// Malformed wire input yields a parse_error response, not a panic.
    #[test]
    fn malformed_input_yields_parse_error_response() -> TestResult {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair()?;
        let mut r = router();
        writeln!(a, "{{not json")?;
        a.flush()?;
        assert_eq!(handle_connection(&mut b, &mut r)?, 1);
        let mut line = String::new();
        BufReader::new(&mut a).read_line(&mut line)?;
        let resp: Response = serde_json::from_str(line.trim())?;
        assert_eq!(resp.error.map(|e| e.code()), Some("parse_error"));
        Ok(())
    }

    /// serve() binds the socket, unlinks stale files first, and answers a
    /// real client end-to-end.
    #[test]
    fn serve_answers_real_client() -> TestResult {
        let dir = std::env::temp_dir().join(format!("k8netd-rpc-{}", std::process::id()));
        let sock = dir.join("control.sock");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        std::fs::write(&sock, b"stale")?; // stale file must be unlinked

        let server_sock = sock.clone();
        let handle = std::thread::spawn(move || {
            let _ = serve(&server_sock, router());
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut client = loop {
            if let Ok(c) = std::os::unix::net::UnixStream::connect(&sock) {
                break c;
            }
            if std::time::Instant::now() > deadline {
                panic!("control socket never became connectable");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };

        let mut r = router(); // separate state for the direct assertion below
        create_net(&mut r, "192.168.124.0/24");
        let req = Request::new("GetNetwork", Some(json!({"name": "net0"})), json!(9));
        writeln!(client, "{}", serde_json::to_string(&req)?)?;
        client.flush()?;
        let mut line = String::new();
        BufReader::new(&client).read_line(&mut line)?;
        let resp: Response = serde_json::from_str(line.trim())?;
        // The served instance has fresh state: unknown network → not_found,
        // which proves the request was routed through the full stack.
        assert_eq!(resp.error.map(|e| e.code()), Some("not_found"));

        drop(client);
        // serve() loops forever by design; detach rather than block the test.
        std::mem::forget(handle);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // TASK-001 (SPEC-CAPISHIM-HYPERVISOR-INTEGRATION REQ-010 / VC-06):
    // PublishPort allocator contract. Red phase: pins the `PublishPort`
    // routing, `ControlPlane::publish_port`, `MemoryControlPlane::
    // with_publish_range`, `MemoryControlPlane::from_store`, and the
    // `k8netd_core::state` persistence seam. Compile failure on those seams
    // is the expected red evidence until the engineer wires them.
    // -----------------------------------------------------------------------

    /// Builds a PublishPort request for `(port, vm_port)`.
    fn pub_req(port: &str, vm_port: u16, id: i64) -> Request {
        Request::new(
            "PublishPort",
            Some(json!({"port": port, "vm_port": vm_port})),
            json!(id),
        )
    }

    /// Creates network `net0` plus one attached port with the given MAC,
    /// the minimum state REQ-010 allows publishing against.
    fn attached_port(r: &mut Router<MemoryControlPlane>, name: &str, mac: &str) {
        create_net(r, "192.168.124.0/24");
        r.dispatch(Request::new("CreatePort", Some(json!({ "name": name })), json!(2)));
        let att = Request::new(
            "AttachPort",
            Some(json!({"port": name, "network": "net0", "mac": mac})),
            json!(3),
        );
        let resp = r.dispatch(att);
        assert!(resp.error.is_none(), "setup: attach of {name} must succeed");
    }

    /// Extracts `host_port` from a successful PublishPort response.
    fn host_port_of(resp: Response) -> u16 {
        resp.result.unwrap()["host_port"].as_u64().unwrap() as u16
    }

    /// REQ-010 / VC-06: identical (port, vm_port) re-publish returns the
    /// same host_port from the default 20000-21000 range.
    #[test]
    fn publish_port_idempotent_same_params_same_host_port() -> TestResult {
        let mut r = router();
        attached_port(&mut r, "vm1", "02:00:00:00:00:01");
        let first = host_port_of(r.dispatch(pub_req("vm1", 6443, 1)));
        let again = host_port_of(r.dispatch(pub_req("vm1", 6443, 2)));
        assert_eq!(first, again, "identical re-publish must return the same host_port");
        assert!(
            (20000..=21000).contains(&first),
            "allocation must come from the default range"
        );
        Ok(())
    }

    /// REQ-010 / VC-06: a different vm_port on the same port gets a distinct
    /// allocation.
    #[test]
    fn publish_port_distinct_vm_port_gets_distinct_host_port() -> TestResult {
        let mut r = router();
        attached_port(&mut r, "vm1", "02:00:00:00:00:01");
        let api = host_port_of(r.dispatch(pub_req("vm1", 6443, 1)));
        let ssh = host_port_of(r.dispatch(pub_req("vm1", 22, 2)));
        assert_ne!(api, ssh, "distinct vm_ports must get distinct host_ports");
        assert!((20000..=21000).contains(&api));
        assert!((20000..=21000).contains(&ssh));
        Ok(())
    }

    /// REQ-010: publishing for a never-created port is a typed not_found.
    #[test]
    fn publish_port_unknown_port_is_error() -> TestResult {
        let mut r = router();
        let resp = r.dispatch(pub_req("ghost", 6443, 1));
        assert_eq!(resp.error.map(|e| e.code()), Some("not_found"));
        Ok(())
    }

    /// REQ-010: created-but-unattached and since-detached ports are not
    /// publishable.
    #[test]
    fn publish_port_unattached_port_is_error() -> TestResult {
        let mut r = router();
        r.dispatch(Request::new("CreatePort", Some(json!({ "name": "lonely" })), json!(1)));
        let resp = r.dispatch(pub_req("lonely", 6443, 2));
        assert_eq!(resp.error.map(|e| e.code()), Some("not_found"), "unattached port");

        attached_port(&mut r, "vm1", "02:00:00:00:00:01");
        assert!(r.dispatch(pub_req("vm1", 6443, 3)).error.is_none());
        r.dispatch(Request::new("DetachPort", Some(json!({ "name": "vm1" })), json!(4)));
        let resp = r.dispatch(pub_req("vm1", 6443, 5));
        assert_eq!(resp.error.map(|e| e.code()), Some("not_found"), "detached port");
        Ok(())
    }

    /// REQ-010 / VC-06: exhaustion is a typed error and leaks no partial
    /// state — the failed publish consumes nothing, so freeing one slot lets
    /// the previously-failing publish succeed. Exhaustion is pinned to the
    /// `conflict` code, matching the existing IPAM PoolExhausted mapping.
    #[test]
    fn publish_range_exhaustion_typed_error_no_partial_state() -> TestResult {
        // Capacity 2: vm1 and vm2 fill the range, vm3 must hit the error.
        let mut r = Router::new(MemoryControlPlane::with_publish_range(20000, 20001));
        attached_port(&mut r, "vm1", "02:00:00:00:00:01");
        attached_port(&mut r, "vm2", "02:00:00:00:00:02");
        attached_port(&mut r, "vm3", "02:00:00:00:00:03");
        assert!(r.dispatch(pub_req("vm1", 6443, 1)).error.is_none());
        assert!(r.dispatch(pub_req("vm2", 6443, 2)).error.is_none());

        let resp = r.dispatch(pub_req("vm3", 6443, 3));
        assert_eq!(
            resp.error.map(|e| e.code()),
            Some("conflict"),
            "exhaustion must surface as the typed conflict code"
        );

        // Free one slot; the failed publish must not have leaked a
        // reservation, so vm3 now succeeds.
        r.dispatch(Request::new("DetachPort", Some(json!({ "name": "vm1" })), json!(4)));
        let got = r.dispatch(pub_req("vm3", 6443, 5));
        assert!(got.error.is_none(), "failed publish must not leak a reservation");
        let hp = host_port_of(got);
        assert!((20000..=20001).contains(&hp));
        assert_eq!(
            host_port_of(r.dispatch(pub_req("vm3", 6443, 6))),
            hp,
            "still idempotent"
        );
        Ok(())
    }

    /// REQ-010 / VC-06: DetachPort of the owning port frees every allocation
    /// it held. Proven by capacity, not allocation order: a full range
    /// becomes publishable again exactly for the freed slots.
    #[test]
    fn detach_port_frees_allocations() -> TestResult {
        // Capacity 3: vm1 holds two allocations (6443 + 22), vm2 one.
        let mut r = Router::new(MemoryControlPlane::with_publish_range(20000, 20002));
        attached_port(&mut r, "vm1", "02:00:00:00:00:01");
        attached_port(&mut r, "vm2", "02:00:00:00:00:02");
        attached_port(&mut r, "vm3", "02:00:00:00:00:03");
        attached_port(&mut r, "vm4", "02:00:00:00:00:04");
        assert!(r.dispatch(pub_req("vm1", 6443, 1)).error.is_none());
        assert!(r.dispatch(pub_req("vm1", 22, 2)).error.is_none());
        assert!(r.dispatch(pub_req("vm2", 6443, 3)).error.is_none());
        assert_eq!(
            r.dispatch(pub_req("vm3", 6443, 4)).error.map(|e| e.code()),
            Some("conflict"),
            "range is full"
        );

        r.dispatch(Request::new("DetachPort", Some(json!({ "name": "vm1" })), json!(5)));
        // Both of vm1's slots are back: vm3 can publish the same pair...
        assert!(r.dispatch(pub_req("vm3", 6443, 6)).error.is_none());
        assert!(r.dispatch(pub_req("vm3", 22, 7)).error.is_none());
        // ...and nothing else was freed.
        assert_eq!(
            r.dispatch(pub_req("vm4", 6443, 8)).error.map(|e| e.code()),
            Some("conflict"),
            "only the detached port's allocations may be freed"
        );
        Ok(())
    }

    /// REQ-010 / VC-06: DeletePort destroys the port together with its
    /// allocations.
    #[test]
    fn delete_port_frees_allocations() -> TestResult {
        let mut r = Router::new(MemoryControlPlane::with_publish_range(20000, 20001));
        attached_port(&mut r, "vm1", "02:00:00:00:00:01");
        attached_port(&mut r, "vm2", "02:00:00:00:00:02");
        attached_port(&mut r, "vm3", "02:00:00:00:00:03");
        assert!(r.dispatch(pub_req("vm1", 6443, 1)).error.is_none());
        assert!(r.dispatch(pub_req("vm2", 6443, 2)).error.is_none());
        assert_eq!(
            r.dispatch(pub_req("vm3", 6443, 3)).error.map(|e| e.code()),
            Some("conflict")
        );

        r.dispatch(Request::new("DeletePort", Some(json!({ "name": "vm1" })), json!(4)));
        assert!(
            r.dispatch(pub_req("vm3", 6443, 5)).error.is_none(),
            "deleted port's allocation must be reclaimed"
        );
        Ok(())
    }

    /// REQ-010 / VC-06: allocations survive a restart through the persisted
    /// state store — a control plane restored from disk re-publishes the
    /// same host_port. Seam pinning: `k8netd_core::state::{StateStore,
    /// save_to_disk, load_from_disk}` carrying `publish_table`, plus
    /// `MemoryControlPlane::from_store`.
    #[test]
    fn publish_allocations_persist_across_restart() -> TestResult {
        let dir = std::env::temp_dir().join(format!("k8netd-publish-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;

        // Session 1: publish through the wire seam and capture the result.
        let mut r = router();
        attached_port(&mut r, "vm1", "02:00:00:00:00:01");
        let h1 = host_port_of(r.dispatch(pub_req("vm1", 6443, 1)));

        // Persist exactly what the daemon owns.
        let mut store = k8netd_core::state::StateStore::default();
        store
            .publish_table
            .entries
            .insert("vm1".to_string(), BTreeMap::from([(6443u16, h1)]));
        k8netd_core::state::save_to_disk(&store, &dir)?;

        // Session 2: a fresh daemon loads state.json and re-publishes.
        let restored = k8netd_core::state::load_from_disk(&dir)?;
        assert_eq!(
            restored.publish_table.entries["vm1"][&6443], h1,
            "publish table must survive the disk round trip"
        );
        let mut r2 = Router::new(MemoryControlPlane::from_store(restored));
        attached_port(&mut r2, "vm1", "02:00:00:00:00:01");
        let h2 = host_port_of(r2.dispatch(pub_req("vm1", 6443, 2)));
        assert_eq!(h1, h2, "restored allocator must honor persisted allocations");

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
