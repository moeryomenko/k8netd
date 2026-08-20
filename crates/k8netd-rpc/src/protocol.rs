//! JSON-RPC 2.0 protocol envelope, typed errors, and version guard (spec
//! REQ-001, VC-06).
//!
//! TASK-004 (test-first): the `tests` module below defines the contract for
//! the protocol layer. The types do not exist yet, so the tests fail to
//! compile (red phase). TASK-005 implements the types in this file to make
//! the tests pass; the tests module stays at the bottom of the file per Rust
//! convention.

use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The k8netd protocol version carried in every request's `version` field
/// (spec REQ-001). The spec does not pin a literal value; this is the value
/// this daemon speaks. [`Request::parse`] rejects any other value with an
/// `invalid_params` error.
pub const PROTOCOL_VERSION: &str = "1.0";

/// A JSON-RPC 2.0 request envelope with the mandatory `version` field
/// (spec REQ-001).
///
/// Construct with [`Request::new`], which fills `jsonrpc` and `version`;
/// decode wire bytes with [`Request::parse`], which enforces the envelope
/// shape and the version guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// The JSON-RPC version; always `"2.0"`.
    pub jsonrpc: String,
    /// The k8netd protocol version; must equal [`PROTOCOL_VERSION`].
    pub version: String,
    /// The method name, e.g. `"CreateNetwork"`.
    pub method: String,
    /// The method parameters, if any.
    pub params: Option<Value>,
    /// The request id, echoed back in the response.
    pub id: Value,
}

impl Request {
    /// Creates a request with the fixed `jsonrpc` and `version` fields.
    pub fn new(method: impl Into<String>, params: Option<Value>, id: Value) -> Request {
        Request {
            jsonrpc: "2.0".to_string(),
            version: PROTOCOL_VERSION.to_string(),
            method: method.into(),
            params,
            id,
        }
    }

    /// Parses and validates a request from its wire JSON.
    ///
    /// Malformed JSON is rejected with [`RpcError::ParseError`]; a
    /// well-formed envelope that is missing `jsonrpc`, `version`, `method`,
    /// or `id` is rejected with [`RpcError::InvalidRequest`]; a `version`
    /// that differs from [`PROTOCOL_VERSION`] is rejected with
    /// [`RpcError::InvalidParams`].
    pub fn parse(input: &str) -> Result<Request, RpcError> {
        #[derive(Deserialize)]
        struct Raw {
            jsonrpc: Option<String>,
            version: Option<String>,
            method: Option<String>,
            params: Option<Value>,
            id: Option<Value>,
        }

        let raw: Raw = serde_json::from_str(input).map_err(|_| RpcError::ParseError)?;
        let jsonrpc = match raw.jsonrpc {
            Some(v) if v == "2.0" => v,
            _ => return Err(RpcError::InvalidRequest),
        };
        let version = raw.version.ok_or(RpcError::InvalidRequest)?;
        if version != PROTOCOL_VERSION {
            return Err(RpcError::InvalidParams);
        }
        let method = raw.method.ok_or(RpcError::InvalidRequest)?;
        let id = raw.id.ok_or(RpcError::InvalidRequest)?;
        Ok(Request {
            jsonrpc,
            version,
            method,
            params: raw.params,
            id,
        })
    }
}

/// A typed k8netd RPC error (spec REQ-001).
///
/// Serializes as `{ "code": "...", "message": "..." }`; deserialization maps
/// the `code` string back to the typed variant. The JSON-RPC 2.0 protocol
/// errors (`parse_error`, `invalid_request`, `method_not_found`,
/// `invalid_params`) share the envelope with the domain codes
/// (`not_found`, `already_exists`, `conflict`, `internal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// The request payload was not valid JSON.
    ParseError,
    /// The payload was valid JSON but not a well-formed request.
    InvalidRequest,
    /// The request named a method this daemon does not implement.
    MethodNotFound,
    /// A parameter was missing, mistyped, or failed validation.
    InvalidParams,
    /// The referenced object does not exist.
    NotFound,
    /// The object already exists with identical parameters.
    AlreadyExists,
    /// The object exists with conflicting parameters.
    Conflict,
    /// An internal daemon failure.
    Internal,
}

impl RpcError {
    /// Returns the machine-readable wire code.
    pub fn code(&self) -> &'static str {
        match self {
            RpcError::ParseError => "parse_error",
            RpcError::InvalidRequest => "invalid_request",
            RpcError::MethodNotFound => "method_not_found",
            RpcError::InvalidParams => "invalid_params",
            RpcError::NotFound => "not_found",
            RpcError::AlreadyExists => "already_exists",
            RpcError::Conflict => "conflict",
            RpcError::Internal => "internal",
        }
    }

    /// Returns a non-empty human-readable message for the code.
    pub fn message(&self) -> String {
        match self {
            RpcError::ParseError => "invalid JSON payload".to_string(),
            RpcError::InvalidRequest => "request is not a valid JSON-RPC request".to_string(),
            RpcError::MethodNotFound => "unknown method".to_string(),
            RpcError::InvalidParams => "invalid parameters".to_string(),
            RpcError::NotFound => "object not found".to_string(),
            RpcError::AlreadyExists => "object already exists".to_string(),
            RpcError::Conflict => "object exists with conflicting parameters".to_string(),
            RpcError::Internal => "internal server error".to_string(),
        }
    }

    /// Resolves a wire code back to its typed variant.
    fn from_code(code: &str) -> Option<RpcError> {
        match code {
            "parse_error" => Some(RpcError::ParseError),
            "invalid_request" => Some(RpcError::InvalidRequest),
            "method_not_found" => Some(RpcError::MethodNotFound),
            "invalid_params" => Some(RpcError::InvalidParams),
            "not_found" => Some(RpcError::NotFound),
            "already_exists" => Some(RpcError::AlreadyExists),
            "conflict" => Some(RpcError::Conflict),
            "internal" => Some(RpcError::Internal),
            _ => None,
        }
    }
}

impl Serialize for RpcError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("RpcError", 2)?;
        state.serialize_field("code", self.code())?;
        state.serialize_field("message", &self.message())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for RpcError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            code: String,
        }

        let raw = Raw::deserialize(deserializer)?;
        let code = raw.code;
        RpcError::from_code(&code).ok_or_else(|| serde::de::Error::custom(format!("unknown rpc error code: {code}")))
    }
}

/// Deserializes the `result` field, preserving an explicit JSON `null` as
/// `Some(Value::Null)` instead of collapsing it to `None`, so a null result
/// round-trips and stays distinguishable from an absent field.
fn deserialize_result<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

/// A JSON-RPC 2.0 response envelope (spec REQ-001).
///
/// Exactly one of `result` or `error` is set. Success responses serialize
/// with a `result` field and no `error` field; error responses serialize
/// with the `error` object and no `result` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// The JSON-RPC version; always `"2.0"`.
    pub jsonrpc: String,
    /// The result payload; present on success. An explicit JSON `null`
    /// result is preserved as `Some(Value::Null)`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_result"
    )]
    pub result: Option<Value>,
    /// The typed error; present on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    /// The request id, echoed from the request.
    pub id: Value,
}

impl Response {
    /// Creates a success response carrying `result` for `id`.
    pub fn ok(id: Value, result: Value) -> Response {
        Response {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Creates an error response carrying `error` for `id`.
    pub fn err(id: Value, error: RpcError) -> Response {
        Response {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

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
