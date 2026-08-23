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
use k8netd_core::model::{IpPool, MacAddr, Network, Port};
use serde_json::{Value, json};

use crate::protocol::{Request, Response, RpcError};

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
#[derive(Default)]
pub struct MemoryControlPlane {
    networks: BTreeMap<String, NetworkEntry>,
    ports: BTreeMap<String, Port>,
}

impl MemoryControlPlane {
    pub fn new() -> Self {
        Self::default()
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
        Ok(Value::Null)
    }

    fn allocate_ip(&mut self, params: &Value) -> Result<Value, RpcError> {
        let net = str_param(params, "network")?;
        let mac: MacAddr = str_param(params, "mac")?.parse().map_err(|_| RpcError::InvalidParams)?;
        let entry = self.networks.get_mut(net).ok_or(RpcError::NotFound)?;
        let ip = entry.ipam.allocate(mac).map_err(ipam_error)?;
        Ok(json!({ "ip": ip.to_string() }))
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
        let ip1 = alloc(&mut r, "02:00:00:00:00:01").result.unwrap()["ip"]
            .as_str()
            .unwrap()
            .to_string();
        let ip2 = alloc(&mut r, "02:00:00:00:00:02").result.unwrap()["ip"]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(ip1, ip2, "distinct MACs get distinct IPs");
        // Reservation is stable across repeated allocations (REQ-004).
        let again = alloc(&mut r, "02:00:00:00:00:01").result.unwrap()["ip"]
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
}
