//! DHCP server for one network (spec REQ-005, VC-04).
//!
//! TASK-014 (test-first): the `tests` module below defines the contract for
//! the server. The server does not exist yet, so the tests fail to compile
//! (red phase). TASK-015 implements the server in this file to make the
//! tests pass; the tests module stays at the bottom of the file per Rust
//! convention.

use std::net::Ipv4Addr;

use dhcproto::v4::{Decodable, DhcpOption, Encodable, HType, MAGIC, Message, MessageType, Opcode, OptionCode};
use k8netd_core::ipam::Ipam;
use k8netd_core::model::MacAddr;

/// Offset of the DHCPv4 magic cookie inside every packet (RFC 2131 section 4.1).
const MAGIC_COOKIE_OFFSET: usize = 236;
/// Smallest well-formed DHCPv4 packet: the 236-byte fixed header plus the magic cookie.
const MIN_PACKET_SIZE: usize = MAGIC_COOKIE_OFFSET + 4;
/// The `AddressLeaseTime` value delivered in OFFER and ACK, in seconds.
const LEASE_SECONDS: u32 = 3600;

/// DHCP server for one network (spec REQ-005, VC-04).
///
/// One server per network; the `Ipam` (and the `Network` it owns) is the
/// source of the pool, the gateway, and the `AllocateIP` reservations. The
/// server is a pure message handler (plan TASK-015 constraint): raw DHCP
/// bytes in, raw reply bytes out; no I/O, no transport — the switch wires
/// it up in TASK-031.
///
/// `handle` validates the magic cookie itself because `dhcproto` does not.
#[derive(Debug)]
pub struct DhcpServer {
    ipam: Ipam,
    /// The encoded reply produced by the last `handle` call, if any.
    reply_buf: Vec<u8>,
}

impl DhcpServer {
    /// Creates a server over the network owned by `ipam`.
    pub fn new(ipam: Ipam) -> Self {
        DhcpServer {
            ipam,
            reply_buf: Vec::new(),
        }
    }

    /// Processes one raw DHCPv4 packet and returns the reply bytes, if any.
    ///
    /// The reply is owned by the server and valid until the next `handle`
    /// call; the transport copies it to the wire before calling again.
    ///
    /// Returns `None` (no reply) when the packet is empty or truncated, the
    /// magic cookie is wrong, the hardware type is not Ethernet or the
    /// hardware length is not 6, or the message carries no `MessageType`
    /// option. Message types other than Discover and Request (RELEASE,
    /// INFORM, DECLINE, ...) are unanswered: the provider frees allocations
    /// via the `ReleaseIP` RPC, so a guest RELEASE does not free the
    /// binding. A Discover that cannot be honored (no reservation and an
    /// exhausted pool) is also unanswered — RFC 2131 defines NAK only in
    /// answer to a Request.
    pub fn handle(&mut self, packet: &[u8]) -> Option<&[u8]> {
        let encoded = self.process(packet)?;
        self.reply_buf = encoded;
        Some(&self.reply_buf)
    }

    /// Validates `packet` and builds the encoded reply, if any (see
    /// [`handle`](Self::handle) for the no-reply conditions).
    fn process(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < MIN_PACKET_SIZE || packet[MAGIC_COOKIE_OFFSET..MAGIC_COOKIE_OFFSET + 4] != MAGIC {
            return None;
        }
        let msg = Message::from_bytes(packet).ok()?;
        if msg.opcode() != Opcode::BootRequest || msg.htype() != HType::Eth || msg.hlen() != 6 {
            return None;
        }
        let mac = MacAddr::from_bytes(msg.chaddr().try_into().ok()?);
        match msg.opts().msg_type()? {
            MessageType::Discover => self.discover(&msg, mac),
            MessageType::Request => self.request(&msg, mac),
            _ => None,
        }
    }

    /// Answers a DISCOVER: a reserved MAC (an existing `Ipam` binding) is
    /// offered its reserved IP; an unknown MAC is allocated the lowest free
    /// pool address, which becomes its binding, so a retransmitted
    /// DISCOVER re-offers the same IP. An exhausted pool yields no reply.
    fn discover(&mut self, msg: &Message, mac: MacAddr) -> Option<Vec<u8>> {
        let ip = match self.ipam.lookup(mac) {
            Some(ip) => ip,
            None => self.ipam.allocate(mac).ok()?,
        };
        self.reply(msg, ip, MessageType::Offer)
    }

    /// Answers a REQUEST: ACK iff the requested IP is bound to the
    /// requesting MAC (`Ipam::lookup(chaddr) == Some(requested)`) — either
    /// from a prior OFFER in this session or from a reservation that
    /// survived a daemon restart. NAK otherwise (an IP bound to a different
    /// MAC, an IP outside the pool, or the gateway).
    ///
    /// The requested IP is the `RequestedIpAddress` option (50) when present
    /// (SELECTING / INIT-REBOOT semantics). A client in RENEWING state omits
    /// option 50 and puts its current address in `ciaddr` (RFC 2131 section
    /// 4.3.5), so when option 50 is absent the request falls back to
    /// `ciaddr` and is ACKed iff it matches the MAC's binding. A request with
    /// neither option 50 nor a usable `ciaddr` (0.0.0.0) is NAK'd, since the
    /// pool never contains 0.0.0.0.
    fn request(&mut self, msg: &Message, mac: MacAddr) -> Option<Vec<u8>> {
        let requested = match msg.opts().get(OptionCode::RequestedIpAddress) {
            Some(DhcpOption::RequestedIpAddress(ip)) => *ip,
            _ => msg.ciaddr(),
        };
        if self.ipam.lookup(mac) == Some(requested) {
            self.reply(msg, requested, MessageType::Ack)
        } else {
            self.nak(msg)
        }
    }

    /// Builds an OFFER or ACK: a BootReply with the echoed xid, chaddr, and
    /// flags (broadcast bit), `yiaddr` set to the offered IP, and the
    /// REQ-005 options: message type, server identifier (the gateway),
    /// subnet mask (derived from the network CIDR prefix), router
    /// (the gateway), DNS (the gateway), and lease time.
    fn reply(&self, msg: &Message, ip: Ipv4Addr, mtype: MessageType) -> Option<Vec<u8>> {
        let network = self.ipam.network();
        let gateway = network.gateway;
        let mut out = Message::new_with_id(
            msg.xid(),
            Ipv4Addr::UNSPECIFIED,
            ip,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            msg.chaddr(),
        );
        out.set_opcode(Opcode::BootReply);
        out.set_flags(msg.flags());
        out.opts_mut().insert(DhcpOption::MessageType(mtype));
        out.opts_mut().insert(DhcpOption::ServerIdentifier(gateway));
        out.opts_mut()
            .insert(DhcpOption::SubnetMask(netmask(network.cidr.prefix)));
        out.opts_mut().insert(DhcpOption::Router(vec![gateway]));
        out.opts_mut().insert(DhcpOption::DomainNameServer(vec![gateway]));
        out.opts_mut().insert(DhcpOption::AddressLeaseTime(LEASE_SECONDS));
        out.to_vec().ok()
    }

    /// Builds a NAK: a BootReply with the echoed xid and chaddr, `yiaddr`
    /// 0.0.0.0, and only the `MessageType(Nak)` option.
    fn nak(&self, msg: &Message) -> Option<Vec<u8>> {
        let mut out = Message::new_with_id(
            msg.xid(),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            msg.chaddr(),
        );
        out.set_opcode(Opcode::BootReply);
        out.set_flags(msg.flags());
        out.opts_mut().insert(DhcpOption::MessageType(MessageType::Nak));
        out.to_vec().ok()
    }
}

/// Returns the 32-bit network mask for a CIDR prefix length.
fn netmask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::from(u32::MAX << (32 - prefix))
    }
}

#[cfg(test)]
mod tests {
    // Expected API — implemented by TASK-015 to satisfy these tests:
    //
    // pub struct DhcpServer { ... }
    //   - DhcpServer::new(ipam: Ipam) -> Self
    //       one server per network; the Ipam (and the Network it owns) is
    //       the source of the pool, the gateway, and the AllocateIP
    //       reservations (spec REQ-004, REQ-005)
    //   - handle(&mut self, packet: &[u8]) -> Option<Vec<u8>>
    //       pure message handler (plan TASK-015 constraint): raw DHCP
    //       bytes in, raw reply bytes out; no I/O, no transport — the
    //       switch wires it up in TASK-031. Raw bytes (not a decoded
    //       `Message`) because `dhcproto` does not validate the magic
    //       cookie and the server must.
    //
    //   No reply (None) when:
    //     - the packet is empty or truncated
    //     - the magic cookie is wrong (the server must check it)
    //     - htype is not Ethernet or hlen is not 6
    //     - the message carries no MessageType option
    //     - the message type is not Discover or Request (RELEASE, INFORM,
    //       DECLINE, ...: no reply; the provider frees allocations via the
    //       ReleaseIP RPC, so a guest RELEASE does not free the binding)
    //     - a Discover cannot be honored: no reservation for the MAC and
    //       the pool is exhausted (pinned: no reply, not a NAK — RFC 2131
    //       defines NAK only in answer to a REQUEST)
    //
    //   DISCOVER:
    //     - reserved MAC (Ipam::lookup) -> OFFER the reserved IP
    //     - unknown MAC -> Ipam::allocate (lowest free pool address,
    //       TASK-007) and OFFER it; the allocation becomes the MAC's
    //       binding, so a retransmitted DISCOVER re-offers the same IP
    //     - OFFER: opcode BootReply; echoed xid, chaddr, and flags
    //       (broadcast bit); yiaddr = offered IP; options:
    //       MessageType(Offer), ServerIdentifier(gateway),
    //       SubnetMask (derived from the network CIDR prefix),
    //       Router([gateway]), DomainNameServer([gateway]),
    //       AddressLeaseTime(3600)
    //
    //   REQUEST:
    //     - requires the RequestedIpAddress option (50); absent -> NAK
    //     - ACK iff Ipam::lookup(chaddr) == Some(requested): the requested
    //       IP is bound to the requesting MAC — either from a prior OFFER
    //       in this session or from a reservation that survived a daemon
    //       restart (the offer table is ephemeral, the allocation is
    //       persisted per REQ-010; REQ-005 "a reserved MAC always receives
    //       its reserved IP" wins over the "not offered" NAK rule when the
    //       MAC requests its own reserved IP)
    //     - NAK otherwise: an IP offered to a different MAC, an IP outside
    //       the pool, the gateway, or a different IP than the one offered
    //       to this MAC (the binding pins the MAC to its address until
    //       released)
    //     - ACK: same fields and options as the OFFER, with
    //       MessageType(Ack)
    //     - NAK: opcode BootReply; echoed xid and chaddr; yiaddr 0.0.0.0;
    //       options: MessageType(Nak) only
    //
    //   LEASE_SECONDS = 3600 — the AddressLeaseTime value delivered in
    //   OFFER and ACK

    use super::*;
    use dhcproto::v4::{Decodable, DhcpOption, Encodable, Flags, Message, MessageType, Opcode, OptionCode};
    use k8netd_core::ipam::Ipam;
    use k8netd_core::model::{IpPool, MacAddr, Network};
    use std::net::Ipv4Addr;

    const XID: u32 = 0x1122_3344;
    const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 124, 1);
    const LEASE_SECONDS: u32 = 3600;

    const MAC_A: &str = "02:00:00:00:00:01";
    const MAC_B: &str = "02:00:00:00:00:02";
    const MAC_C: &str = "02:00:00:00:00:03";
    const MAC_R: &str = "02:00:00:00:00:05";

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    fn mac_bytes(s: &str) -> [u8; 6] {
        let mut out = [0u8; 6];
        for (i, part) in s.split(':').enumerate() {
            out[i] = u8::from_str_radix(part, 16).unwrap();
        }
        out
    }

    fn lab_pool() -> IpPool {
        IpPool::new(ip(192, 168, 124, 10), ip(192, 168, 124, 200)).unwrap()
    }

    fn lab_network() -> Network {
        Network::new("lab", "192.168.124.0/24", "192.168.124.1", lab_pool()).unwrap()
    }

    fn small_network() -> Network {
        let pool = IpPool::new(ip(192, 168, 124, 10), ip(192, 168, 124, 12)).unwrap();
        Network::new("small", "192.168.124.0/24", "192.168.124.1", pool).unwrap()
    }

    fn net28_network() -> Network {
        let pool = IpPool::new(ip(192, 168, 124, 10), ip(192, 168, 124, 14)).unwrap();
        Network::new("net28", "192.168.124.0/28", "192.168.124.1", pool).unwrap()
    }

    fn server() -> DhcpServer {
        DhcpServer::new(Ipam::new(lab_network()))
    }

    // DHCP packet fixtures (client side).

    fn discover(xid: u32, addr: &str) -> Message {
        let mut msg = Message::new_with_id(
            xid,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac_bytes(addr),
        );
        msg.opts_mut().insert(DhcpOption::MessageType(MessageType::Discover));
        msg
    }

    fn request(xid: u32, addr: &str, requested: Option<Ipv4Addr>) -> Message {
        let mut msg = Message::new_with_id(
            xid,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac_bytes(addr),
        );
        msg.opts_mut().insert(DhcpOption::MessageType(MessageType::Request));
        if let Some(ip) = requested {
            msg.opts_mut().insert(DhcpOption::RequestedIpAddress(ip));
        }
        msg
    }

    /// A RENEWING-state REQUEST (RFC 2131 section 4.3.5): the client omits
    /// option 50 and puts its current address in `ciaddr`.
    fn renew(xid: u32, addr: &str, ciaddr: Ipv4Addr) -> Message {
        let mut msg = Message::new_with_id(
            xid,
            ciaddr,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac_bytes(addr),
        );
        msg.opts_mut().insert(DhcpOption::MessageType(MessageType::Request));
        msg
    }

    // Exchange helpers: encode, hand to the server, decode the reply.

    fn encode(msg: &Message) -> Vec<u8> {
        msg.to_vec().unwrap()
    }

    fn decode(bytes: &[u8]) -> Message {
        Message::from_bytes(bytes).unwrap()
    }

    fn exchange(server: &mut DhcpServer, msg: &Message) -> Option<Message> {
        server.handle(&encode(msg)).map(decode)
    }

    // Option extractors.

    fn opt_subnet_mask(msg: &Message) -> Option<Ipv4Addr> {
        match msg.opts().get(OptionCode::SubnetMask) {
            Some(DhcpOption::SubnetMask(ip)) => Some(*ip),
            _ => None,
        }
    }

    fn opt_router(msg: &Message) -> Option<Vec<Ipv4Addr>> {
        match msg.opts().get(OptionCode::Router) {
            Some(DhcpOption::Router(ips)) => Some(ips.clone()),
            _ => None,
        }
    }

    fn opt_dns(msg: &Message) -> Option<Vec<Ipv4Addr>> {
        match msg.opts().get(OptionCode::DomainNameServer) {
            Some(DhcpOption::DomainNameServer(ips)) => Some(ips.clone()),
            _ => None,
        }
    }

    fn opt_lease(msg: &Message) -> Option<u32> {
        match msg.opts().get(OptionCode::AddressLeaseTime) {
            Some(DhcpOption::AddressLeaseTime(secs)) => Some(*secs),
            _ => None,
        }
    }

    fn opt_server_id(msg: &Message) -> Option<Ipv4Addr> {
        match msg.opts().get(OptionCode::ServerIdentifier) {
            Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
            _ => None,
        }
    }

    // Shared assertions.

    fn assert_reply(msg: &Message, xid: u32, addr: &str, mtype: MessageType) {
        assert_eq!(msg.opcode(), Opcode::BootReply, "opcode must be BootReply");
        assert_eq!(msg.xid(), xid, "xid must be echoed");
        assert_eq!(msg.chaddr(), &mac_bytes(addr)[..], "chaddr must be echoed");
        assert_eq!(msg.opts().msg_type(), Some(mtype), "message type");
    }

    /// The four options REQ-005 requires in OFFER and ACK.
    fn assert_req3_options(msg: &Message, mask: Ipv4Addr) {
        assert_eq!(opt_subnet_mask(msg), Some(mask), "subnet mask option");
        assert_eq!(
            opt_router(msg),
            Some(vec![GATEWAY]),
            "router option must be the gateway"
        );
        assert_eq!(opt_dns(msg), Some(vec![GATEWAY]), "dns option must be the gateway");
        assert_eq!(opt_lease(msg), Some(LEASE_SECONDS), "lease time option");
    }

    // REQ-1: DISCOVER/OFFER/REQUEST/ACK flow.

    #[test]
    fn discover_unknown_mac_yields_offer_with_pool_ip() {
        let mut server = server();
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        assert_reply(&offer, XID, MAC_A, MessageType::Offer);
        assert_eq!(offer.yiaddr(), ip(192, 168, 124, 10), "lowest free pool address");
    }

    #[test]
    fn request_offered_ip_yields_ack() {
        let mut server = server();
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let offered = offer.yiaddr();
        let ack = exchange(&mut server, &request(XID, MAC_A, Some(offered))).expect("an ACK is expected");
        assert_reply(&ack, XID, MAC_A, MessageType::Ack);
        assert_eq!(ack.yiaddr(), offered);
    }

    #[test]
    fn discover_retransmit_reoffers_same_ip() {
        let mut server = server();
        let first = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let second = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        assert_eq!(
            first.yiaddr(),
            second.yiaddr(),
            "the binding pins the MAC to its address"
        );
    }

    #[test]
    fn offer_and_ack_echo_broadcast_flag() {
        let mut server = server();
        let mut d = discover(XID, MAC_A);
        d.set_flags(Flags::default().set_broadcast());
        let offer = exchange(&mut server, &d).expect("an OFFER is expected");
        assert!(offer.flags().broadcast(), "OFFER must echo the broadcast flag");
        let mut r = request(XID, MAC_A, Some(offer.yiaddr()));
        r.set_flags(Flags::default().set_broadcast());
        let ack = exchange(&mut server, &r).expect("an ACK is expected");
        assert!(ack.flags().broadcast(), "ACK must echo the broadcast flag");
    }

    // REQ-2: a reserved MAC (pre-allocated via Ipam) always receives its reserved IP.

    #[test]
    fn reserved_mac_receives_reserved_ip_in_offer() {
        let mut ipam = Ipam::new(lab_network());
        let reserved = ipam.allocate(mac(MAC_R)).expect("pool has free addresses");
        let mut server = DhcpServer::new(ipam);
        let offer = exchange(&mut server, &discover(XID, MAC_R)).expect("an OFFER is expected");
        assert_reply(&offer, XID, MAC_R, MessageType::Offer);
        assert_eq!(offer.yiaddr(), reserved, "the reserved IP must be offered");
    }

    #[test]
    fn reserved_mac_receives_reserved_ip_in_ack() {
        let mut ipam = Ipam::new(lab_network());
        let reserved = ipam.allocate(mac(MAC_R)).expect("pool has free addresses");
        let mut server = DhcpServer::new(ipam);
        exchange(&mut server, &discover(XID, MAC_R)).expect("an OFFER is expected");
        let ack = exchange(&mut server, &request(XID, MAC_R, Some(reserved))).expect("an ACK is expected");
        assert_reply(&ack, XID, MAC_R, MessageType::Ack);
        assert_eq!(ack.yiaddr(), reserved, "the reserved IP must be ACKed");
    }

    #[test]
    fn reserved_mac_offer_precedes_pool_order() {
        // MAC_A and MAC_B take the two lowest addresses; MAC_R's reservation
        // is .12. MAC_R must be offered .12, not the lowest free address.
        let mut ipam = Ipam::new(lab_network());
        ipam.allocate(mac(MAC_A)).unwrap(); // .10
        ipam.allocate(mac(MAC_B)).unwrap(); // .11
        let reserved = ipam.allocate(mac(MAC_R)).unwrap(); // .12
        let mut server = DhcpServer::new(ipam);
        let offer = exchange(&mut server, &discover(XID, MAC_R)).expect("an OFFER is expected");
        assert_eq!(offer.yiaddr(), reserved, "reservation wins over pool order");
        assert_ne!(offer.yiaddr(), ip(192, 168, 124, 10), "not the lowest free address");
    }

    // REQ-3: options delivered in OFFER/ACK (subnet mask, router, DNS, lease).

    #[test]
    fn offer_carries_required_options() {
        let mut server = server();
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        assert_req3_options(&offer, ip(255, 255, 255, 0));
    }

    #[test]
    fn ack_carries_required_options() {
        let mut server = server();
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let ack = exchange(&mut server, &request(XID, MAC_A, Some(offer.yiaddr()))).expect("an ACK is expected");
        assert_req3_options(&ack, ip(255, 255, 255, 0));
    }

    #[test]
    fn subnet_mask_derived_from_cidr_prefix() {
        let mut server = DhcpServer::new(Ipam::new(net28_network()));
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        assert_eq!(
            opt_subnet_mask(&offer),
            Some(ip(255, 255, 255, 240)),
            "the /28 mask must be derived from the CIDR, not hardcoded"
        );
    }

    // REQ-4: an unknown MAC (no reservation) gets a pool address.

    #[test]
    fn two_unknown_macs_get_distinct_pool_ips() {
        let mut server = server();
        let a = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let b = exchange(&mut server, &discover(XID, MAC_B)).expect("an OFFER is expected");
        assert_eq!(a.yiaddr(), ip(192, 168, 124, 10));
        assert_eq!(b.yiaddr(), ip(192, 168, 124, 11), "the next pool address");
        assert_ne!(a.yiaddr(), b.yiaddr(), "pool addresses are never duplicated");
    }

    // REQ-5: a REQUEST for an IP not offered to the client MAC yields a NAK.

    #[test]
    fn request_ip_offered_to_other_mac_yields_nak() {
        let mut server = server();
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let nak = exchange(&mut server, &request(XID, MAC_B, Some(offer.yiaddr()))).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_B, MessageType::Nak);
    }

    #[test]
    fn nak_carries_expected_fields() {
        let mut server = server();
        exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let nak = exchange(&mut server, &request(XID, MAC_B, Some(ip(192, 168, 124, 10)))).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_B, MessageType::Nak);
        assert_eq!(nak.yiaddr(), Ipv4Addr::UNSPECIFIED, "a NAK must not carry an address");
        assert_eq!(opt_server_id(&nak), None, "a NAK carries only the message type");
        assert_eq!(opt_subnet_mask(&nak), None);
        assert_eq!(opt_router(&nak), None);
        assert_eq!(opt_dns(&nak), None);
        assert_eq!(opt_lease(&nak), None);
    }

    #[test]
    fn request_ip_outside_pool_yields_nak() {
        let mut server = server();
        let nak = exchange(&mut server, &request(XID, MAC_A, Some(ip(192, 168, 124, 5)))).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_A, MessageType::Nak);
    }

    #[test]
    fn request_gateway_ip_yields_nak() {
        let mut server = server();
        let nak = exchange(&mut server, &request(XID, MAC_A, Some(GATEWAY))).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_A, MessageType::Nak);
    }

    #[test]
    fn request_without_requested_ip_option_yields_nak() {
        let mut server = server();
        let nak = exchange(&mut server, &request(XID, MAC_A, None)).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_A, MessageType::Nak);
    }

    // TASK-010X: RENEWING-state REQUEST (RFC 2131 section 4.3.5) — option 50
    // absent, the client's current address in ciaddr. The server must ACK a
    // renewal whose ciaddr matches the IPAM binding for the client MAC, and
    // NAK anything else. Option 50, when present, stays authoritative.

    #[test]
    fn renewing_request_with_matching_ciaddr_yields_ack() {
        // The client renews at T1: no option 50, ciaddr = its bound address.
        let mut server = server();
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let bound = offer.yiaddr(); // .10, now bound to MAC_A
        let ack = exchange(&mut server, &renew(XID, MAC_A, bound)).expect("an ACK is expected");
        assert_reply(&ack, XID, MAC_A, MessageType::Ack);
        assert_eq!(ack.yiaddr(), bound, "the ACK must carry the renewed ciaddr");
        assert_req3_options(&ack, ip(255, 255, 255, 0));
    }

    #[test]
    fn reserved_mac_renewing_with_ciaddr_yields_ack() {
        // The production scenario: a reserved MAC (pre-allocated via Ipam)
        // renews at T1 with ciaddr only.
        let mut ipam = Ipam::new(lab_network());
        let reserved = ipam.allocate(mac(MAC_R)).expect("pool has free addresses");
        let mut server = DhcpServer::new(ipam);
        let ack = exchange(&mut server, &renew(XID, MAC_R, reserved)).expect("an ACK is expected");
        assert_reply(&ack, XID, MAC_R, MessageType::Ack);
        assert_eq!(ack.yiaddr(), reserved, "the reserved IP must be ACKed on renewal");
    }

    #[test]
    fn renewing_request_with_ciaddr_bound_to_other_mac_yields_nak() {
        // ciaddr is bound to a different MAC: no unauthorized renewal.
        let mut server = server();
        let offer_a = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected"); // .10
        exchange(&mut server, &discover(XID, MAC_B)).expect("an OFFER is expected"); // .11
        let nak = exchange(&mut server, &renew(XID, MAC_B, offer_a.yiaddr())).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_B, MessageType::Nak);
    }

    #[test]
    fn renewing_request_with_unbound_ciaddr_yields_nak() {
        // ciaddr is a pool address no MAC is bound to: not a valid renewal.
        let mut server = server();
        exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected"); // .10
        let nak = exchange(&mut server, &renew(XID, MAC_A, ip(192, 168, 124, 11))).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_A, MessageType::Nak);
    }

    #[test]
    fn renewing_request_with_ciaddr_outside_pool_yields_nak() {
        let mut server = server();
        exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let nak = exchange(&mut server, &renew(XID, MAC_A, ip(192, 168, 124, 5))).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_A, MessageType::Nak);
    }

    #[test]
    fn renewing_request_with_ciaddr_equal_gateway_yields_nak() {
        let mut server = server();
        exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let nak = exchange(&mut server, &renew(XID, MAC_A, GATEWAY)).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_A, MessageType::Nak);
    }

    #[test]
    fn request_without_option50_and_unspecified_ciaddr_yields_nak() {
        // Neither option 50 nor a usable ciaddr: NAK even when the MAC has a
        // binding (0.0.0.0 is never a valid renewal target).
        let mut server = server();
        exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        let nak = exchange(&mut server, &request(XID, MAC_A, None)).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_A, MessageType::Nak);
    }

    #[test]
    fn request_with_option50_takes_precedence_over_ciaddr() {
        // A REQUEST carrying both option 50 and a ciaddr is judged by option
        // 50 (SELECTING/INIT-REBOOT semantics), never the ciaddr.
        let mut server = server();
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected"); // .10
        let mut r = request(XID, MAC_A, Some(offer.yiaddr()));
        r.set_ciaddr(ip(192, 168, 124, 11)); // ciaddr claims an unbound address
        let ack = exchange(&mut server, &r).expect("an ACK is expected");
        assert_reply(&ack, XID, MAC_A, MessageType::Ack);
        assert_eq!(ack.yiaddr(), offer.yiaddr(), "option 50 wins over ciaddr");
    }

    #[test]
    fn request_with_option50_mismatch_naks_even_when_ciaddr_matches() {
        // option 50 requests an IP bound to another MAC while ciaddr matches
        // this MAC's own binding: option 50 governs, so the request is NAK'd.
        let mut server = server();
        let offer_a = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected"); // .10
        exchange(&mut server, &discover(XID, MAC_B)).expect("an OFFER is expected"); // .11
        let mut r = request(XID, MAC_A, Some(ip(192, 168, 124, 11))); // option 50 = MAC_B's .11
        r.set_ciaddr(offer_a.yiaddr()); // ciaddr = MAC_A's own .10
        let nak = exchange(&mut server, &r).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_A, MessageType::Nak);
    }

    // Edge cases.

    #[test]
    fn released_reservation_mac_gets_pool_address_not_old_ip() {
        // MAC_A's reservation is released (provider called ReleaseIP); MAC_B
        // takes the freed .10; MAC_A must then get a pool address, not .10.
        let mut ipam = Ipam::new(lab_network());
        let old_ip = ipam.allocate(mac(MAC_A)).expect("pool has free addresses"); // .10
        ipam.release(mac(MAC_A)).expect("the reservation is active");
        let mut server = DhcpServer::new(ipam);
        let b = exchange(&mut server, &discover(XID, MAC_B)).expect("an OFFER is expected");
        assert_eq!(b.yiaddr(), old_ip, "the freed address is the lowest free one");
        let a = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        assert_ne!(a.yiaddr(), old_ip, "the released MAC must not get its old IP back");
        assert_eq!(a.yiaddr(), ip(192, 168, 124, 11), "the next free pool address");
    }

    #[test]
    fn request_different_ip_than_offered_yields_nak() {
        let mut server = server();
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected"); // .10
        let nak = exchange(&mut server, &request(XID, MAC_A, Some(ip(192, 168, 124, 11)))).expect("a NAK is expected");
        assert_reply(&nak, XID, MAC_A, MessageType::Nak);
        assert_ne!(offer.yiaddr(), ip(192, 168, 124, 11));
    }

    #[test]
    fn exhausted_pool_discover_yields_no_response() {
        // The whole 3-address pool is reserved; a new MAC DISCOVERs.
        // Pinned behavior: no response (not a NAK — RFC 2131 defines NAK
        // only in answer to a REQUEST).
        let mut ipam = Ipam::new(small_network());
        ipam.allocate(mac(MAC_A)).unwrap(); // .10
        ipam.allocate(mac(MAC_B)).unwrap(); // .11
        ipam.allocate(mac(MAC_C)).unwrap(); // .12
        let mut server = DhcpServer::new(ipam);
        assert_eq!(
            exchange(&mut server, &discover(XID, MAC_R)),
            None,
            "no address to offer"
        );
        // The reserved MACs are unaffected.
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        assert_eq!(offer.yiaddr(), ip(192, 168, 124, 10));
    }

    #[test]
    fn offer_and_ack_server_identifier_is_gateway() {
        let mut server = server();
        let offer = exchange(&mut server, &discover(XID, MAC_A)).expect("an OFFER is expected");
        assert_eq!(opt_server_id(&offer), Some(GATEWAY), "OFFER server identifier");
        let ack = exchange(&mut server, &request(XID, MAC_A, Some(offer.yiaddr()))).expect("an ACK is expected");
        assert_eq!(opt_server_id(&ack), Some(GATEWAY), "ACK server identifier");
    }

    #[test]
    fn bad_magic_cookie_yields_no_response() {
        let mut server = server();
        let mut bytes = encode(&discover(XID, MAC_A));
        bytes[236..240].copy_from_slice(&[0xEE; 4]); // corrupt the magic cookie
        assert_eq!(server.handle(&bytes), None, "a wrong magic cookie must not be answered");
    }

    #[test]
    fn truncated_and_empty_packets_yield_no_response() {
        let mut server = server();
        assert_eq!(server.handle(&[]), None, "empty packet");
        let bytes = encode(&discover(XID, MAC_A));
        assert_eq!(server.handle(&bytes[..50]), None, "truncated packet");
        assert_eq!(server.handle(&bytes[..200]), None, "truncated before the magic cookie");
    }

    #[test]
    fn bootrequest_without_message_type_yields_no_response() {
        let mut server = server();
        let mut msg = Message::new_with_id(
            XID,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &mac_bytes(MAC_A),
        );
        msg.opts_mut()
            .insert(DhcpOption::ClientIdentifier(mac_bytes(MAC_A).to_vec()));
        assert_eq!(exchange(&mut server, &msg), None, "no MessageType option, no reply");
    }

    #[test]
    fn non_ethernet_hlen_yields_no_response() {
        let mut server = server();
        let mut msg = Message::new_with_id(
            XID,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &[0x02, 0x00, 0x00], // hlen 3, not an Ethernet MAC
        );
        msg.opts_mut().insert(DhcpOption::MessageType(MessageType::Discover));
        assert_eq!(
            server.handle(&encode(&msg)),
            None,
            "hlen != 6 must not be answered (or panic)"
        );
    }
}
