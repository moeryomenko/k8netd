//! JSON-RPC 2.0 protocol envelope, typed errors, and version guard (spec
//! REQ-001, VC-06).
//!
//! TASK-004 (test-first): the `tests` module below defines the contract for
//! the protocol layer. The types do not exist yet, so the tests fail to
//! compile (red phase). TASK-005 implements the types in this file to make
//! the tests pass; the tests module stays at the bottom of the file per Rust
//! convention.

#[cfg(test)]
mod tests {
    // Expected API — implemented by TASK-005 to satisfy these tests:
    //
    // pub const PROTOCOL_VERSION: &str
    //   - the k8netd protocol version carried in every request's `version`
    //     field. The spec (REQ-001) does not pin a literal value; the tests
    //     reference the constant so the implementer chooses the value. The
    //     wrong-version tests use "9.9", which must differ from it.
    //
    // pub struct Request { jsonrpc: String, version: String, method: String,
    //                      params: Option<Value>, id: Value }
    //   - Request::new(method: impl Into<String>, params: Option<Value>,
    //     id: Value) -> Request; fills jsonrpc = "2.0" and
    //     version = PROTOCOL_VERSION
    //   - Request::parse(&str) -> Result<Request, RpcError>; rejects
    //     malformed JSON (ParseError), structurally invalid requests —
    //     missing id/method/version/jsonrpc (InvalidRequest) — and a
    //     version != PROTOCOL_VERSION (InvalidParams)
    //   - Serialize, Deserialize, PartialEq, Eq, Clone, Debug
    //
    // pub struct Response { jsonrpc: String, result: Option<Value>,
    //                       error: Option<RpcError>, id: Value }
    //   - Response::ok(id: Value, result: Value) -> Response
    //   - Response::err(id: Value, error: RpcError) -> Response
    //   - result and error are mutually exclusive on the wire: error
    //     responses serialize with the `error` object and no `result` field
    //   - Serialize, Deserialize, PartialEq, Eq, Clone, Debug
    //
    // pub enum RpcError { ParseError, InvalidRequest, MethodNotFound,
    //                     InvalidParams, NotFound, AlreadyExists, Conflict,
    //                     Internal }
    //   - code(&self) -> &'static str: "parse_error", "invalid_request",
    //     "method_not_found", "invalid_params", "not_found",
    //     "already_exists", "conflict", "internal"
    //   - message(&self) -> String (non-empty)
    //   - Serialize/Deserialize as { "code": "...", "message": "..." }
    //   - PartialEq, Eq, Clone, Debug

    use super::*;
    use serde_json::{Value, json};

    // REQ-1: JSON-RPC 2.0 request serialization/deserialization round-trip
    // (method, params, id).

    #[test]
    fn request_round_trip_object_params() {
        let req = Request::new(
            "CreateNetwork",
            Some(json!({"name": "lab", "cidr": "192.168.124.0/24"})),
            json!("1"),
        );
        let s = serde_json::to_string(&req).unwrap();
        let restored: Request = Request::parse(&s).expect("serialized request must parse");
        assert_eq!(req, restored);
    }

    #[test]
    fn request_round_trip_null_params() {
        let req = Request::new("GetNetwork", None, json!("1"));
        let s = serde_json::to_string(&req).unwrap();
        let restored: Request = Request::parse(&s).expect("serialized request must parse");
        assert_eq!(req, restored);
    }

    #[test]
    fn request_serializes_full_envelope() {
        let req = Request::new(
            "CreateNetwork",
            Some(json!({"name": "lab", "cidr": "192.168.124.0/24"})),
            json!("1"),
        );
        let s = serde_json::to_string(&req).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["version"].as_str(), Some(PROTOCOL_VERSION));
        assert_eq!(v["method"], "CreateNetwork");
        assert_eq!(v["params"], json!({"name": "lab", "cidr": "192.168.124.0/24"}));
        assert_eq!(v["id"], "1");
    }

    // REQ-2: JSON-RPC 2.0 response serialization/deserialization round-trip
    // (result, id).

    #[test]
    fn response_round_trip_result() {
        let resp = Response::ok(json!("1"), json!({"name": "lab"}));
        let s = serde_json::to_string(&resp).unwrap();
        let restored: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, restored);
    }

    #[test]
    fn response_round_trip_null_result() {
        let resp = Response::ok(json!("1"), Value::Null);
        let s = serde_json::to_string(&resp).unwrap();
        let restored: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, restored);
    }

    // REQ-3: typed error codes — each of not_found, already_exists,
    // invalid_params, conflict, internal serializes with its code and maps
    // back to the typed error.

    #[test]
    fn error_codes_round_trip_all_five() {
        let cases = [
            (RpcError::NotFound, "not_found"),
            (RpcError::AlreadyExists, "already_exists"),
            (RpcError::InvalidParams, "invalid_params"),
            (RpcError::Conflict, "conflict"),
            (RpcError::Internal, "internal"),
        ];
        for (err, code) in cases {
            let s = serde_json::to_string(&err).unwrap();
            let v: Value = serde_json::from_str(&s).unwrap();
            assert_eq!(v["code"], code);
            assert!(
                v["message"].as_str().is_some_and(|m| !m.is_empty()),
                "error {code} must carry a non-empty message"
            );
            let restored: RpcError = serde_json::from_str(&s).unwrap();
            assert_eq!(restored, err);
        }
    }

    // REQ-4: mandatory `version` field in every request; version-mismatch
    // requests are rejected.

    #[test]
    fn request_accepts_current_version() {
        let v = json!({
            "jsonrpc": "2.0",
            "version": PROTOCOL_VERSION,
            "method": "GetNetwork",
            "params": null,
            "id": "1",
        });
        let req = Request::parse(&v.to_string()).expect("current-version request must parse");
        assert_eq!(req, Request::new("GetNetwork", None, json!("1")));
    }

    #[test]
    fn request_rejects_missing_version() {
        let v = json!({
            "jsonrpc": "2.0",
            "method": "GetNetwork",
            "params": null,
            "id": "1",
        });
        assert!(Request::parse(&v.to_string()).is_err());
    }

    #[test]
    fn request_rejects_wrong_version() {
        let v = json!({
            "jsonrpc": "2.0",
            "version": "9.9",
            "method": "GetNetwork",
            "params": null,
            "id": "1",
        });
        let err = Request::parse(&v.to_string()).unwrap_err();
        assert_eq!(err.code(), "invalid_params");
    }

    // REQ-5: error response shape — the error object carries code + message,
    // and an error response has no `result` field.

    #[test]
    fn error_response_shape() {
        let resp = Response::err(json!("1"), RpcError::NotFound);
        let s = serde_json::to_string(&resp).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], "1");
        assert_eq!(v["error"]["code"], "not_found");
        assert!(
            v["error"]["message"].as_str().is_some_and(|m| !m.is_empty()),
            "error object must carry a non-empty message"
        );
        assert!(v.get("result").is_none(), "error response must not carry a result");
    }

    #[test]
    fn response_error_round_trip() {
        let resp = Response::err(json!("1"), RpcError::Conflict);
        let s = serde_json::to_string(&resp).unwrap();
        let restored: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(resp, restored);
    }

    // Edge cases.

    #[test]
    fn error_method_not_found_round_trip() {
        // Unknown method names surface as a JSON-RPC method_not_found error.
        let err = RpcError::MethodNotFound;
        let s = serde_json::to_string(&err).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["code"], "method_not_found");
        let restored: RpcError = serde_json::from_str(&s).unwrap();
        assert_eq!(restored, RpcError::MethodNotFound);
    }

    #[test]
    fn request_rejects_malformed_json() {
        let err = Request::parse("{not json").unwrap_err();
        assert_eq!(err.code(), "parse_error");
    }

    #[test]
    fn request_rejects_missing_id() {
        let mut v = json!({
            "jsonrpc": "2.0",
            "version": PROTOCOL_VERSION,
            "method": "GetNetwork",
            "params": null,
        });
        v.as_object_mut().unwrap().remove("id");
        assert!(Request::parse(&v.to_string()).is_err());
    }
}
