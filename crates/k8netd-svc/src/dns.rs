//! DNS forwarder on the gateway address (spec REQ-006, VC-05).
//!
//! A pure forwarder: no local zones (CoreDNS in the cluster is untouched),
//! no caching, no state per query.
//!
//! TASK-016 (test-first): the `tests` module below defines the contract for
//! the forwarder. The forwarder does not exist yet, so the tests fail to
//! compile (red phase). TASK-017 implements the forwarder in this file to
//! make the tests pass; the tests module stays at the bottom of the file
//! per Rust convention.
//!
//! The production wiring (real UDP to the pinned upstreams on `:53`,
//! per-upstream timeout) is TASK-017/TASK-031; the test seam is the
//! `UpstreamSender` trait pinned in the tests module doc comment.

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};

/// A failed attempt against one upstream (pinned by the TASK-016 test seam).
///
/// The production sender (TASK-017/TASK-031) maps its transport failures to
/// these variants; `Timeout` is the per-upstream timeout the trait doc pins.
#[derive(Debug)]
pub enum UpstreamError {
    /// The upstream did not answer within the per-upstream timeout (the
    /// production sender must enforce one and never block indefinitely).
    Timeout,
    /// The upstream refused the query.
    Refused,
    /// Transport-level send/recv failure.
    Io(std::io::Error),
}

impl Clone for UpstreamError {
    /// Clones the error. `std::io::Error` is not `Clone`, so the `Io`
    /// variant's clone preserves the error's kind and message.
    fn clone(&self) -> Self {
        match self {
            UpstreamError::Timeout => UpstreamError::Timeout,
            UpstreamError::Refused => UpstreamError::Refused,
            UpstreamError::Io(err) => UpstreamError::Io(std::io::Error::new(err.kind(), err.to_string())),
        }
    }
}

/// Test seam (TASK-016 design note): a pluggable upstream sender so the
/// forwarder is testable without real UDP. The production implementation
/// (TASK-017/TASK-031) sends the query over UDP to the pinned upstream's
/// `:53` and returns the response bytes.
///
/// Object-safe: the forwarder holds `Vec<Box<dyn UpstreamSender>>`.
pub trait UpstreamSender: Send + Sync + 'static {
    /// Sends one raw DNS query to the upstream and returns the raw response
    /// bytes, or an [`UpstreamError`] when the attempt failed.
    fn send(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamError>;
}

/// A pure DNS forwarder (spec REQ-006, VC-05): no local zones, no caching,
/// stateless per query.
///
/// The forwarder holds its upstreams as trait objects in try order; the
/// switch wires it up in TASK-031.
pub struct DnsForwarder {
    upstreams: Vec<Box<dyn UpstreamSender>>,
}

impl DnsForwarder {
    /// Creates a forwarder over the given upstreams, in try order.
    ///
    /// An empty list is accepted: every query then gets SERVFAIL.
    pub fn new(upstreams: Vec<Box<dyn UpstreamSender>>) -> Self {
        DnsForwarder { upstreams }
    }

    /// Forwards one raw DNS query and returns the response bytes to relay to
    /// the requester, or `None` (drop, no response) when the packet is
    /// undecodable or carries no questions.
    ///
    /// Pinned behavior:
    /// - the query is relayed byte-for-byte to the upstreams, one at a time
    ///   in list order (sequential); header flags such as TC are not
    ///   interpreted
    /// - the first response that decodes, has message_type `Response`, and
    ///   echoes the query's ID is relayed back byte-for-byte (same ID, same
    ///   answers); a response that fails those checks (undecodable,
    ///   mismatched ID, not a response) is a failed attempt: the next
    ///   upstream is tried
    /// - if every attempt fails (Timeout/Refused/Io, or only bad responses),
    ///   a SERVFAIL response is built and returned: the query's ID echoed,
    ///   opcode Query, message_type Response, rcode ServFail, empty
    ///   question/answer/authority/additional sections — never a hang,
    ///   never a panic
    /// - `handle` takes `&self`: the forwarder holds no state per query; a
    ///   failed query does not affect the next one
    pub fn handle(&self, packet: &[u8]) -> Option<Vec<u8>> {
        // The forwarder must decode to forward: garbage is dropped, never
        // forwarded, never a panic. The raw bytes are what gets relayed
        // (byte-for-byte), so only the ID and the question count come off
        // the decode.
        let query = Message::from_vec(packet).ok()?;
        if query.queries.is_empty() {
            return None;
        }
        let id = query.metadata.id;
        for upstream in &self.upstreams {
            if let Ok(response) = upstream.send(packet)
                && let Ok(decoded) = Message::from_vec(&response)
                && decoded.metadata.message_type == MessageType::Response
                && decoded.metadata.id == id
            {
                return Some(response);
            }
        }
        Self::servfail(id)
    }

    /// Builds the SERVFAIL sent when every upstream attempt fails: the
    /// query's ID echoed, opcode Query, rcode ServFail, empty sections.
    fn servfail(id: u16) -> Option<Vec<u8>> {
        Message::error_msg(id, OpCode::Query, ResponseCode::ServFail)
            .to_vec()
            .ok()
    }
}

#[cfg(test)]
mod tests {
    // Expected API — implemented by TASK-017 to satisfy these tests:
    //
    // #[derive(Debug, Clone)]
    // pub enum UpstreamError {
    //     Timeout, // the upstream did not answer within the per-upstream
    //              // timeout (the production sender must enforce one and
    //              // never block indefinitely)
    //     Refused, // the upstream refused the query
    //     Io(std::io::Error), // transport-level send/recv failure
    // }
    //
    // /// Test seam (TASK-016 design note): a pluggable upstream sender so
    // /// the forwarder is testable without real UDP. The production
    // /// implementation (TASK-017/TASK-031) sends the query over UDP to
    // /// the pinned upstream's `:53` and returns the response bytes.
    // /// Object-safe: the forwarder holds `Vec<Box<dyn UpstreamSender>>`.
    // pub trait UpstreamSender: Send + Sync {
    //     fn send(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamError>;
    // }
    //
    // /// A pure DNS forwarder (spec REQ-006, VC-05): no local zones, no
    // /// caching, stateless per query.
    // pub struct DnsForwarder { /* upstreams: Vec<Box<dyn UpstreamSender>> */ }
    //
    // impl DnsForwarder {
    //     /// Creates a forwarder over the given upstreams, in try order.
    //     /// An empty list is accepted: every query then gets SERVFAIL.
    //     pub fn new(upstreams: Vec<Box<dyn UpstreamSender>>) -> Self;
    //
    //     /// Forwards one raw DNS query and returns the response bytes to
    //     /// relay to the requester, or `None` (drop, no response) when
    //     /// the packet is undecodable or carries no questions.
    //     ///
    //     /// Pinned behavior:
    //     /// - the query is relayed byte-for-byte to the upstreams, one at
    //     ///   a time in list order (sequential); header flags such as TC
    //     ///   are not interpreted
    //     /// - the first response that decodes, has message_type
    //     ///   `Response`, and echoes the query's ID is relayed back
    //     ///   byte-for-byte (same ID, same answers); a response that
    //     ///   fails those checks (undecodable, mismatched ID, not a
    //     ///   response) is a failed attempt: the next upstream is tried
    //     /// - if every attempt fails (Timeout/Refused/Io, or only bad
    //     ///   responses), a SERVFAIL response is built and returned: the
    //     ///   query's ID echoed, opcode Query, message_type Response,
    //     ///   rcode ServFail, empty question/answer/authority/additional
    //     ///   sections — never a hang, never a panic
    //     /// - `handle` takes `&self`: the forwarder holds no state per
    //     ///   query; a failed query does not affect the next one
    //     pub fn handle(&self, packet: &[u8]) -> Option<Vec<u8>>;
    // }

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

    const QUERY_ID: u16 = 0x1234;
    const OTHER_ID: u16 = 0xBEEF;
    const QUERY_NAME: &str = "upstream.example";
    const A_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const AAAA_IP: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x42);
    const TTL: u32 = 300;

    fn name(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    /// A standard A query for `qname` with the given ID.
    fn query(id: u16, qname: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(name(qname), RecordType::A));
        msg
    }

    /// A response to the query: the echoed ID, NoError, one A and one AAAA
    /// answer for the queried name.
    fn response_for(query: &Message, qname: &str, a: Ipv4Addr, aaaa: Ipv6Addr) -> Message {
        let mut msg = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        msg.add_answer(Record::from_rdata(name(qname), TTL, RData::A(A::from(a))));
        msg.add_answer(Record::from_rdata(name(qname), TTL, RData::AAAA(AAAA::from(aaaa))));
        msg
    }

    fn encode(msg: &Message) -> Vec<u8> {
        msg.to_vec().unwrap()
    }

    fn decode(bytes: &[u8]) -> Message {
        Message::from_vec(bytes).unwrap()
    }

    fn order() -> Arc<Mutex<Vec<&'static str>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn order_of(rec: &Arc<Mutex<Vec<&'static str>>>) -> Vec<&'static str> {
        rec.lock().unwrap().clone()
    }

    /// A canned upstream: records every query it receives (and its position
    /// in the shared call order) and returns the pinned result, every time.
    struct Stub {
        label: &'static str,
        result: Result<Vec<u8>, UpstreamError>,
        sent: Arc<Mutex<Vec<Vec<u8>>>>,
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    fn stub(
        label: &'static str,
        result: Result<Vec<u8>, UpstreamError>,
        order: &Arc<Mutex<Vec<&'static str>>>,
    ) -> (Stub, Arc<Mutex<Vec<Vec<u8>>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Stub {
                label,
                result,
                sent: sent.clone(),
                order: order.clone(),
            },
            sent,
        )
    }

    impl UpstreamSender for Stub {
        fn send(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamError> {
            self.sent.lock().unwrap().push(query.to_vec());
            self.order.lock().unwrap().push(self.label);
            self.result.clone()
        }
    }

    /// A stateful upstream: fails its first `fail_calls` sends with
    /// Timeout, then answers with the canned response. Proves the
    /// forwarder does not remember a failed attempt.
    struct FlakyStub {
        label: &'static str,
        canned: Vec<u8>,
        fail_calls: Mutex<usize>,
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    impl UpstreamSender for FlakyStub {
        fn send(&self, query: &[u8]) -> Result<Vec<u8>, UpstreamError> {
            self.order.lock().unwrap().push(self.label);
            let _ = query;
            let mut fails = self.fail_calls.lock().unwrap();
            if *fails > 0 {
                *fails -= 1;
                return Err(UpstreamError::Timeout);
            }
            Ok(self.canned.clone())
        }
    }

    /// Builds the forwarder under test (pinned constructor, object-safe
    /// seam: `dyn UpstreamSender`).
    fn forwarder<S: UpstreamSender>(stubs: Vec<S>) -> DnsForwarder {
        DnsForwarder::new(
            stubs
                .into_iter()
                .map(|s| Box::new(s) as Box<dyn UpstreamSender>)
                .collect(),
        )
    }

    /// The wire shape of the forwarder-built failure response (pinned:
    /// SERVFAIL with the echoed ID and empty sections).
    fn assert_servfail(bytes: &[u8], id: u16) {
        let msg = decode(bytes);
        assert_eq!(msg.metadata.id, id, "the query ID must be echoed");
        assert_eq!(
            msg.metadata.message_type,
            MessageType::Response,
            "a response to the requester"
        );
        assert_eq!(msg.metadata.op_code, OpCode::Query);
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::ServFail,
            "pinned: SERVFAIL, not REFUSED"
        );
        assert!(msg.queries.is_empty(), "no question section");
        assert!(msg.answers.is_empty(), "no answer section");
        assert!(msg.authorities.is_empty(), "no authority section");
        assert!(msg.additionals.is_empty(), "no additional section");
    }

    // REQ-1: a query is forwarded to the pinned upstream and the response
    // is relayed back to the requester unchanged (same ID, same answers).

    #[test]
    fn query_is_forwarded_and_response_relayed_unchanged() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let canned = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        let canned_bytes = encode(&canned);
        let (stub, sent) = stub("up0", Ok(canned_bytes.clone()), &rec);
        let fwd = forwarder(vec![stub]);

        let relayed = fwd.handle(&encode(&q)).expect("a response is relayed");

        let sent_q = sent.lock().unwrap();
        assert_eq!(sent_q.len(), 1, "the query goes to the upstream exactly once");
        assert_eq!(sent_q[0], encode(&q), "the query is relayed byte-for-byte");
        assert_eq!(relayed, canned_bytes, "the response is relayed byte-for-byte");
    }

    #[test]
    fn relayed_response_preserves_id_and_answers() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let canned = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        let (stub, _sent) = stub("up0", Ok(encode(&canned)), &rec);
        let fwd = forwarder(vec![stub]);

        let msg = decode(&fwd.handle(&encode(&q)).expect("a response is relayed"));

        assert_eq!(msg.metadata.id, QUERY_ID, "same ID");
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(msg.answers.len(), 2, "same answers");
        let a = &msg.answers[0];
        assert_eq!(a.name, name("upstream.example."));
        assert_eq!(a.dns_class, DNSClass::IN);
        assert_eq!(a.ttl, TTL);
        assert_eq!(a.data, RData::A(A::from(A_IP)));
        assert_eq!(msg.answers[1].data, RData::AAAA(AAAA::from(AAAA_IP)));
    }

    // Edge: ID 0 is a valid query ID (boundary of the u16 ID field) and
    // must not be treated as "no ID".

    #[test]
    fn query_with_zero_id_is_forwarded_and_relayed() {
        let rec = order();
        let q = query(0, QUERY_NAME);
        let canned = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        let (stub, _sent) = stub("up0", Ok(encode(&canned)), &rec);
        let fwd = forwarder(vec![stub]);

        let relayed = fwd.handle(&encode(&q)).expect("a response is relayed");

        assert_eq!(decode(&relayed).metadata.id, 0, "ID 0 is echoed, not dropped");
    }

    // Edge: a query with the TC bit set. Pinned: the forwarder does not
    // interpret header flags; the query (and a truncated response) is
    // relayed as-is.

    #[test]
    fn tc_bit_on_query_is_forwarded_as_is() {
        let rec = order();
        let mut q = query(QUERY_ID, QUERY_NAME);
        q.metadata.truncation = true;
        let mut canned = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        canned.metadata.truncation = true;
        let canned_bytes = encode(&canned);
        let (stub, sent) = stub("up0", Ok(canned_bytes.clone()), &rec);
        let fwd = forwarder(vec![stub]);

        let relayed = fwd.handle(&encode(&q)).expect("a response is relayed");

        let sent_q = sent.lock().unwrap();
        assert_eq!(
            sent_q[0],
            encode(&q),
            "the TC query is relayed byte-for-byte, flags not interpreted"
        );
        assert_eq!(relayed, canned_bytes, "the truncated response is relayed byte-for-byte");
    }

    // REQ-2: with multiple pinned upstreams, the first successful
    // upstream's response is used.

    #[test]
    fn first_upstream_success_wins_second_never_called() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let first = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        let second = response_for(&q, QUERY_NAME, Ipv4Addr::new(203, 0, 113, 9), AAAA_IP);
        let (s0, _sent0) = stub("up0", Ok(encode(&first)), &rec);
        let (s1, sent1) = stub("up1", Ok(encode(&second)), &rec);
        let fwd = forwarder(vec![s0, s1]);

        let relayed = fwd.handle(&encode(&q)).expect("a response is relayed");

        assert_eq!(
            relayed,
            encode(&first),
            "the first successful upstream's response is used"
        );
        assert_ne!(relayed, encode(&second));
        assert_eq!(order_of(&rec), vec!["up0"], "the second upstream is never called");
        assert!(sent1.lock().unwrap().is_empty());
    }

    #[test]
    fn failed_upstream_falls_through_to_next() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let good = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        let good_bytes = encode(&good);
        let (s0, _sent0) = stub("up0", Err(UpstreamError::Timeout), &rec);
        let (s1, _sent1) = stub("up1", Ok(good_bytes.clone()), &rec);
        let fwd = forwarder(vec![s0, s1]);

        let relayed = fwd.handle(&encode(&q)).expect("a response is relayed");

        assert_eq!(relayed, good_bytes, "the next upstream's response is used");
        assert_eq!(order_of(&rec), vec!["up0", "up1"], "upstream 0 is tried first");
    }

    // Edge: a response with a mismatched ID (a response to a different
    // query, spoofed or misrouted). Pinned: it is dropped, the next
    // upstream is tried.

    #[test]
    fn mismatched_response_id_is_dropped_next_upstream_tried() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let mut mismatched = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        mismatched.metadata.id = OTHER_ID;
        let good = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        let good_bytes = encode(&good);
        let (s0, _sent0) = stub("up0", Ok(encode(&mismatched)), &rec);
        let (s1, _sent1) = stub("up1", Ok(good_bytes.clone()), &rec);
        let fwd = forwarder(vec![s0, s1]);

        let relayed = fwd.handle(&encode(&q)).expect("a response is relayed");

        assert_eq!(relayed, good_bytes, "the mismatched response is not relayed");
        assert_eq!(order_of(&rec), vec!["up0", "up1"]);
    }

    // REQ-3: if all upstreams fail (timeout/refused), the requester gets a
    // SERVFAIL response — never a hang, never a crash.

    #[test]
    fn all_upstreams_timeout_yields_servfail() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let (s0, _sent0) = stub("up0", Err(UpstreamError::Timeout), &rec);
        let fwd = forwarder(vec![s0]);

        // `handle` is synchronous and returns: a dead upstream cannot hang
        // the requester (the per-upstream timeout is enforced by the
        // production sender, pinned in the trait doc).
        let relayed = fwd.handle(&encode(&q)).expect("a response is produced, never a hang");

        assert_servfail(&relayed, QUERY_ID);
    }

    #[test]
    fn mixed_timeout_and_refused_yields_servfail() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let (s0, _sent0) = stub("up0", Err(UpstreamError::Timeout), &rec);
        let (s1, _sent1) = stub("up1", Err(UpstreamError::Refused), &rec);
        let fwd = forwarder(vec![s0, s1]);

        let relayed = fwd.handle(&encode(&q)).expect("a response is produced");

        assert_servfail(&relayed, QUERY_ID);
        assert_eq!(order_of(&rec), vec!["up0", "up1"], "every upstream is tried");
    }

    // Edge: no upstreams configured at all. Pinned: `new` accepts the
    // empty list and every query gets SERVFAIL.

    #[test]
    fn no_upstreams_yields_servfail() {
        let fwd = forwarder::<Stub>(vec![]);
        let q = query(QUERY_ID, QUERY_NAME);

        let relayed = fwd.handle(&encode(&q)).expect("a response is produced");

        assert_servfail(&relayed, QUERY_ID);
    }

    // Edge: a single upstream whose response carries a mismatched ID.
    // Pinned: the mismatched response is dropped and the exhausted
    // forwarder answers SERVFAIL (with the query's ID, not the foreign one).

    #[test]
    fn mismatched_response_id_with_single_upstream_yields_servfail() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let mut mismatched = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        mismatched.metadata.id = OTHER_ID;
        let (s0, _sent0) = stub("up0", Ok(encode(&mismatched)), &rec);
        let fwd = forwarder(vec![s0]);

        let relayed = fwd.handle(&encode(&q)).expect("a response is produced");

        assert_servfail(&relayed, QUERY_ID);
    }

    // REQ-4: a malformed (undecodable) DNS packet yields no response
    // (pinned in the doc comment, consistent with the DHCP server's
    // no-reply-for-garbage convention). The forwarder must decode the
    // packet to forward it; garbage is dropped, never forwarded, never
    // a panic.

    #[test]
    fn undecodable_packet_yields_no_response() {
        let rec = order();
        let (s0, sent0) = stub("up0", Ok(Vec::new()), &rec);
        let fwd = forwarder(vec![s0]);

        let garbage = vec![0xFFu8; 32];
        assert_eq!(fwd.handle(&garbage), None, "garbage is dropped, no panic");
        assert_eq!(fwd.handle(&[0u8; 8]), None, "a truncated header is dropped");
        assert!(sent0.lock().unwrap().is_empty(), "nothing is forwarded upstream");
    }

    #[test]
    fn empty_packet_yields_no_response() {
        let rec = order();
        let (s0, sent0) = stub("up0", Ok(Vec::new()), &rec);
        let fwd = forwarder(vec![s0]);

        assert_eq!(fwd.handle(&[]), None, "an empty packet is dropped");
        assert!(sent0.lock().unwrap().is_empty(), "nothing is forwarded upstream");
    }

    // Edge: a query with an empty qname. Pinned interpretation: a
    // decodable message with qdcount == 0 (no questions). There is
    // nothing to forward; it is dropped, not sent upstream.

    #[test]
    fn zero_question_query_yields_no_response() {
        let rec = order();
        let (s0, sent0) = stub("up0", Ok(Vec::new()), &rec);
        let fwd = forwarder(vec![s0]);
        let q = Message::new(QUERY_ID, MessageType::Query, OpCode::Query);

        assert_eq!(fwd.handle(&encode(&q)), None, "no questions, no response");
        assert!(sent0.lock().unwrap().is_empty(), "nothing is forwarded upstream");
    }

    // Edge: the forwarder holds no state (stateless per query). Pinned by
    // the `&self` receiver on `handle` (the compiler enforces it) and by
    // these two tests.

    #[test]
    fn repeated_queries_are_independent() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let canned = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        let canned_bytes = encode(&canned);
        let (stub, sent) = stub("up0", Ok(canned_bytes.clone()), &rec);
        let fwd = forwarder(vec![stub]);

        let first = fwd.handle(&encode(&q)).expect("a response is relayed");
        let second = fwd.handle(&encode(&q)).expect("a response is relayed");

        assert_eq!(first, canned_bytes);
        assert_eq!(second, canned_bytes, "the same query gets the same result");
        assert_eq!(sent.lock().unwrap().len(), 2, "each query is forwarded independently");
    }

    #[test]
    fn failed_query_does_not_poison_the_next() {
        let rec = order();
        let q = query(QUERY_ID, QUERY_NAME);
        let canned = response_for(&q, QUERY_NAME, A_IP, AAAA_IP);
        let canned_bytes = encode(&canned);
        let flaky = FlakyStub {
            label: "up0",
            canned: canned_bytes.clone(),
            fail_calls: Mutex::new(1),
            order: rec.clone(),
        };
        let fwd = forwarder(vec![flaky]);

        let first = fwd.handle(&encode(&q)).expect("a response is produced");
        assert_servfail(&first, QUERY_ID);
        let second = fwd.handle(&encode(&q)).expect("a response is relayed");
        assert_eq!(second, canned_bytes, "a failed attempt is not remembered");
    }
}
