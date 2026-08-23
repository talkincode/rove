//! Built-in read-only SNMP agent (v2c now, v3/USM in `usm`).
//!
//! Design rules (see issue #61):
//! - **Read-only, forever.** GET / GETNEXT / GETBULK only. SET answers
//!   `notWritable`; traps and informs do not exist here.
//! - **Fail closed.** A source-address allowlist gates every packet before a
//!   single byte is parsed; bad community/user names are silently dropped
//!   (counted, never logged per-packet — no log storms from scanners).
//! - **Fault isolation.** The agent is one UDP task. Parse errors drop the
//!   datagram and bump `snmpInASNParseErrs`; a dead SNMP socket can never
//!   affect the proxy data plane.
//!
//! The MIB view is rebuilt per request from live [`TrafficStats`] — a few
//! dozen entries, so snapshot cost is irrelevant next to the UDP round-trip.

pub mod ber;
pub mod mib;
pub mod usm;

use crate::config::SnmpConfig;
use crate::stats::{StartClock, TrafficStats};
use ber::{Oid, Reader, Value, Writer};
use mib::{AgentCountersSnapshot, MibInputs, MibView, NodeRole};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Enterprise OID base: `.1.3.6.1.4.1.32473.61`.
///
/// 32473 is the enterprise number RFC 5612 reserves for documentation — a
/// deliberate placeholder until the project owns a registered PEN. `.61`
/// matches the issue that specified this subtree.
pub const ENTERPRISE_BASE: &[u32] = &[1, 3, 6, 1, 4, 1, 32473, 61];

const SNMP_VERSION_2C: i64 = 1;
const SNMP_VERSION_3: i64 = 3;

/// RFC 3416 error-status codes used by this agent.
const ERR_TOO_BIG: i64 = 1;
const ERR_NOT_WRITABLE: i64 = 17;

/// Never emit more repetition rounds than this in one GETBULK response,
/// regardless of what max-repetitions asks for. Keeps worst-case work and
/// response size bounded even against abusive requests.
const MAX_REPETITIONS_CAP: i64 = 64;

/// Response size budget (bytes). Well under the 65507-byte UDP maximum so
/// the answer survives any sane path MTU handling; GETBULK truncates on a
/// varbind boundary to fit, as RFC 3416 §4.2.3 allows.
const RESPONSE_BUDGET: usize = 16 * 1024;

/// Who this agent says it is (feeds the identity scalars).
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub node_id: String,
    pub role: NodeRole,
    pub version: String,
}

/// Live agent packet counters (mirrored into the `snmp` MIB group).
#[derive(Debug, Default)]
pub struct AgentCounters {
    in_pkts: AtomicU32,
    in_bad_versions: AtomicU32,
    in_bad_community_names: AtomicU32,
    in_asn_parse_errs: AtomicU32,
}

impl AgentCounters {
    fn snapshot(&self) -> AgentCountersSnapshot {
        AgentCountersSnapshot {
            in_pkts: self.in_pkts.load(Ordering::Relaxed),
            in_bad_versions: self.in_bad_versions.load(Ordering::Relaxed),
            in_bad_community_names: self.in_bad_community_names.load(Ordering::Relaxed),
            in_asn_parse_errs: self.in_asn_parse_errs.load(Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    pub fn bad_community_names(&self) -> u32 {
        self.in_bad_community_names.load(Ordering::Relaxed)
    }
}

/// A parsed request PDU (GET / GETNEXT / GETBULK / SET).
#[derive(Debug)]
struct RequestPdu {
    tag: u8,
    request_id: i64,
    /// error-status for GET*, non-repeaters for GETBULK.
    field1: i64,
    /// error-index for GET*, max-repetitions for GETBULK.
    field2: i64,
    bindings: Vec<(Oid, Value)>,
}

/// The protocol engine, independent of any socket so tests can drive it with
/// raw datagrams.
pub struct AgentCore {
    identity: AgentIdentity,
    base: Oid,
    community: Vec<u8>,
    allow: Vec<ipnet::IpNet>,
    stats: Arc<TrafficStats>,
    clock: StartClock,
    counters: AgentCounters,
    usm: Option<usm::UsmAgent>,
}

impl AgentCore {
    pub fn new(
        cfg: &SnmpConfig,
        identity: AgentIdentity,
        stats: Arc<TrafficStats>,
    ) -> anyhow::Result<AgentCore> {
        cfg.validate()?;
        let allow = cfg
            .allow_cidrs
            .iter()
            .map(|c| c.parse::<ipnet::IpNet>())
            .collect::<Result<Vec<_>, _>>()?;
        let usm = if cfg.v3_users.is_empty() {
            None
        } else {
            Some(usm::UsmAgent::new(
                &cfg.v3_users,
                &identity.node_id,
                &cfg.state_path,
            )?)
        };
        Ok(AgentCore {
            identity,
            base: Oid::new(ENTERPRISE_BASE),
            community: cfg.community.clone().into_bytes(),
            allow,
            stats,
            clock: StartClock::now(),
            counters: AgentCounters::default(),
            usm,
        })
    }

    #[cfg(test)]
    pub fn counters(&self) -> &AgentCounters {
        &self.counters
    }

    fn allowed(&self, ip: IpAddr) -> bool {
        // Normalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) so a dual-stack
        // socket still matches plain IPv4 allowlist entries.
        let ip = ip.to_canonical();
        self.allow.iter().any(|net| net.contains(&ip))
    }

    fn bump(&self, counter: &AtomicU32) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Handle one datagram; `Some(bytes)` is the response to send back.
    /// `None` means silent drop — the only outcome for anything unauthorized
    /// or malformed.
    pub fn handle_datagram(&self, buf: &[u8], peer: SocketAddr) -> Option<Vec<u8>> {
        self.bump(&self.counters.in_pkts);
        if !self.allowed(peer.ip()) {
            return None;
        }
        let mut reader = Reader::new(buf);
        let mut msg = match reader.read_sequence() {
            Ok(msg) => msg,
            Err(_) => {
                self.bump(&self.counters.in_asn_parse_errs);
                return None;
            }
        };
        let version = match msg.read_integer() {
            Ok(v) => v,
            Err(_) => {
                self.bump(&self.counters.in_asn_parse_errs);
                return None;
            }
        };
        match version {
            SNMP_VERSION_2C => self.handle_v2c(&mut msg),
            SNMP_VERSION_3 => match &self.usm {
                Some(usm) => usm.handle(self, buf, &mut msg),
                None => {
                    self.bump(&self.counters.in_bad_versions);
                    None
                }
            },
            _ => {
                self.bump(&self.counters.in_bad_versions);
                None
            }
        }
    }

    fn handle_v2c(&self, msg: &mut Reader<'_>) -> Option<Vec<u8>> {
        let community = match msg.read_octet_string() {
            Ok(c) => c,
            Err(_) => {
                self.bump(&self.counters.in_asn_parse_errs);
                return None;
            }
        };
        // Empty configured community = v2c disabled. Constant-time compare,
        // and rejection is silent: scanners get nothing to distinguish.
        if self.community.is_empty() || !constant_time_eq(&self.community, community) {
            self.bump(&self.counters.in_bad_community_names);
            return None;
        }
        let pdu = match parse_pdu(msg) {
            Ok(pdu) => pdu,
            Err(_) => {
                self.bump(&self.counters.in_asn_parse_errs);
                return None;
            }
        };
        let response = self.answer(&pdu)?;
        Some(encode_message(community, &response))
    }

    /// Compute the Response-PDU for a request, shared by v2c and (later) v3.
    fn answer(&self, pdu: &RequestPdu) -> Option<ResponsePdu> {
        let view = self.build_view();
        match pdu.tag {
            ber::TAG_GET_REQUEST => {
                let bindings = pdu
                    .bindings
                    .iter()
                    .map(|(oid, _)| (oid.clone(), view.get(oid)))
                    .collect();
                Some(ResponsePdu::ok(pdu.request_id, bindings))
            }
            ber::TAG_GET_NEXT_REQUEST => {
                let bindings = pdu
                    .bindings
                    .iter()
                    .map(|(oid, _)| next_binding(&view, oid))
                    .collect();
                Some(ResponsePdu::ok(pdu.request_id, bindings))
            }
            ber::TAG_GET_BULK_REQUEST => Some(self.answer_bulk(&view, pdu)),
            ber::TAG_SET_REQUEST => {
                // Read-only agent, permanently: every SET target is
                // notWritable, pointing at the first varbind.
                Some(ResponsePdu {
                    request_id: pdu.request_id,
                    error_status: ERR_NOT_WRITABLE,
                    error_index: 1,
                    bindings: pdu.bindings.clone(),
                })
            }
            _ => None, // Response/Trap/Inform PDUs are not requests: drop.
        }
    }

    fn answer_bulk(&self, view: &MibView, pdu: &RequestPdu) -> ResponsePdu {
        let non_repeaters = pdu.field1.max(0) as usize;
        let max_repetitions = pdu.field2.clamp(0, MAX_REPETITIONS_CAP) as usize;
        let mut bindings: Vec<(Oid, Value)> = Vec::new();
        let mut budget = RESPONSE_BUDGET;

        let mut push = |bindings: &mut Vec<(Oid, Value)>, oid: Oid, value: Value| -> bool {
            let mut w = Writer::new();
            w.write_oid(&oid);
            w.write_value(&value);
            let cost = w.len() + 4;
            if cost > budget {
                return false;
            }
            budget -= cost;
            bindings.push((oid, value));
            true
        };

        for (oid, _) in pdu.bindings.iter().take(non_repeaters) {
            let (next_oid, value) = next_binding(view, oid);
            if !push(&mut bindings, next_oid, value) {
                return self.too_big(pdu);
            }
        }

        let repeaters: Vec<&(Oid, Value)> = pdu.bindings.iter().skip(non_repeaters).collect();
        let mut cursors: Vec<Oid> = repeaters.iter().map(|(oid, _)| oid.clone()).collect();
        let mut exhausted = vec![false; cursors.len()];
        'rounds: for _ in 0..max_repetitions {
            if exhausted.iter().all(|&done| done) {
                break;
            }
            for (i, cursor) in cursors.iter_mut().enumerate() {
                let (next_oid, value) = if exhausted[i] {
                    (cursor.clone(), Value::EndOfMibView)
                } else {
                    next_binding(view, cursor)
                };
                if matches!(value, Value::EndOfMibView) {
                    exhausted[i] = true;
                }
                *cursor = next_oid.clone();
                if !push(&mut bindings, next_oid, value) {
                    break 'rounds; // truncation on a varbind boundary is legal
                }
            }
        }

        if bindings.is_empty() && !pdu.bindings.is_empty() {
            return self.too_big(pdu);
        }
        ResponsePdu::ok(pdu.request_id, bindings)
    }

    fn too_big(&self, pdu: &RequestPdu) -> ResponsePdu {
        ResponsePdu {
            request_id: pdu.request_id,
            error_status: ERR_TOO_BIG,
            error_index: 0,
            bindings: Vec::new(),
        }
    }

    fn build_view(&self) -> MibView {
        let engine = self.usm.as_ref().map(|u| u.engine_view());
        MibView::build(&MibInputs {
            base: &self.base,
            node_id: &self.identity.node_id,
            node_role: self.identity.role,
            version: &self.identity.version,
            uptime_ticks: self.clock.uptime_ticks(),
            listeners: &self.stats.listener_rows(),
            egress: &self.stats.egress_rows(),
            agent: self.counters.snapshot(),
            engine: engine.as_ref(),
        })
    }
}

/// Constant-time byte comparison for the community string. The XOR-fold
/// runs over the full length regardless of where the first mismatch is;
/// only the (non-secret) length short-circuits.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn next_binding(view: &MibView, oid: &Oid) -> (Oid, Value) {
    match view.next(oid) {
        Some((next_oid, value)) => (next_oid, value),
        None => (oid.clone(), Value::EndOfMibView),
    }
}

#[derive(Debug)]
struct ResponsePdu {
    request_id: i64,
    error_status: i64,
    error_index: i64,
    bindings: Vec<(Oid, Value)>,
}

impl ResponsePdu {
    fn ok(request_id: i64, bindings: Vec<(Oid, Value)>) -> ResponsePdu {
        ResponsePdu {
            request_id,
            error_status: 0,
            error_index: 0,
            bindings,
        }
    }
}

fn parse_pdu(msg: &mut Reader<'_>) -> Result<RequestPdu, ber::BerError> {
    let tag = msg.peek_tag()?;
    let (_, content) = msg.read_tlv()?;
    let mut pdu = Reader::new(content);
    let request_id = pdu.read_integer()?;
    let field1 = pdu.read_integer()?;
    let field2 = pdu.read_integer()?;
    let mut list = pdu.read_sequence()?;
    let mut bindings = Vec::new();
    while !list.is_empty() {
        let mut vb = list.read_sequence()?;
        let oid = vb.read_oid()?;
        let value = vb.read_value()?;
        bindings.push((oid, value));
    }
    Ok(RequestPdu {
        tag,
        request_id,
        field1,
        field2,
        bindings,
    })
}

fn encode_pdu(tag: u8, response: &ResponsePdu) -> Writer {
    let mut list = Writer::new();
    for (oid, value) in &response.bindings {
        let mut vb = Writer::new();
        vb.write_oid(oid);
        vb.write_value(value);
        list = concat(list, Writer::wrap(ber::TAG_SEQUENCE, vb));
    }
    let mut pdu = Writer::new();
    pdu.write_integer(response.request_id);
    pdu.write_integer(response.error_status);
    pdu.write_integer(response.error_index);
    pdu = concat(pdu, Writer::wrap(ber::TAG_SEQUENCE, list));
    Writer::wrap(tag, pdu)
}

fn encode_message(community: &[u8], response: &ResponsePdu) -> Vec<u8> {
    let mut body = Writer::new();
    body.write_integer(SNMP_VERSION_2C);
    body.write_octet_string(community);
    body = concat(body, encode_pdu(ber::TAG_RESPONSE, response));
    Writer::wrap(ber::TAG_SEQUENCE, body).into_bytes()
}

fn concat(a: Writer, b: Writer) -> Writer {
    Writer::from_bytes({
        let mut out = a.into_bytes();
        out.extend_from_slice(&b.into_bytes());
        out
    })
}

/// Bind the UDP socket and serve until the process exits. Callers spawn this
/// on its own task; any error (port in use, socket failure) belongs to the
/// caller's log and never the data plane.
/// Bind the agent socket and return the local address plus the serve
/// future. Split from [`run_agent`] so tests (and callers that want the
/// resolved port) can bind on port 0.
pub async fn bind_agent(
    cfg: SnmpConfig,
    identity: AgentIdentity,
    stats: Arc<TrafficStats>,
) -> anyhow::Result<(
    SocketAddr,
    impl std::future::Future<Output = anyhow::Result<()>>,
)> {
    let core = Arc::new(AgentCore::new(&cfg, identity, stats)?);
    let socket = tokio::net::UdpSocket::bind(&cfg.listen)
        .await
        .map_err(|e| anyhow::anyhow!("snmp: bind {}: {e}", cfg.listen))?;
    let addr = socket.local_addr()?;
    Ok((addr, serve_socket(core, socket)))
}

pub async fn run_agent(
    cfg: SnmpConfig,
    identity: AgentIdentity,
    stats: Arc<TrafficStats>,
) -> anyhow::Result<()> {
    let (addr, serve) = bind_agent(cfg, identity, stats).await?;
    info!(listen = %addr, "snmp agent listening");
    serve.await
}

async fn serve_socket(core: Arc<AgentCore>, socket: tokio::net::UdpSocket) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65535];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(ok) => ok,
            Err(e) => {
                // Transient recv errors (e.g. ICMP-triggered) must not kill
                // the agent; back off briefly and keep serving.
                warn!(error = %e, "snmp recv error");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        if let Some(response) = core.handle_datagram(&buf[..len], peer) {
            if let Err(e) = socket.send_to(&response, peer).await {
                debug!(error = %e, peer = %peer, "snmp send error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SnmpConfig;

    fn test_core(community: &str) -> AgentCore {
        test_core_with(community, Vec::new())
    }

    fn test_core_with(
        community: &str,
        v3_users: Vec<crate::config::SnmpV3UserConfig>,
    ) -> AgentCore {
        let cfg = SnmpConfig {
            enable: true,
            listen: "127.0.0.1:0".to_string(),
            community: community.to_string(),
            v3_users,
            ..SnmpConfig::default()
        };
        let stats = TrafficStats::new();
        stats.record_listener_bytes("web", 100, 200);
        stats.record_egress_bytes("direct", 100, 200);
        AgentCore::new(
            &cfg,
            AgentIdentity {
                node_id: "edge-1".to_string(),
                role: NodeRole::Edge,
                version: "2.0.4".to_string(),
            },
            stats,
        )
        .unwrap()
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:34567".parse().unwrap()
    }

    fn request(community: &str, tag: u8, f1: i64, f2: i64, oids: &[&[u32]]) -> Vec<u8> {
        let mut list = Writer::new();
        for oid in oids {
            let mut vb = Writer::new();
            vb.write_oid(&Oid::new(oid));
            vb.write_null();
            list = concat(list, Writer::wrap(ber::TAG_SEQUENCE, vb));
        }
        let mut pdu = Writer::new();
        pdu.write_integer(7); // request-id
        pdu.write_integer(f1);
        pdu.write_integer(f2);
        pdu = concat(pdu, Writer::wrap(ber::TAG_SEQUENCE, list));
        let mut body = Writer::new();
        body.write_integer(SNMP_VERSION_2C);
        body.write_octet_string(community.as_bytes());
        body = concat(body, Writer::wrap(tag, pdu));
        Writer::wrap(ber::TAG_SEQUENCE, body).into_bytes()
    }

    fn decode_response(bytes: &[u8]) -> (i64, i64, i64, Vec<(Oid, Value)>) {
        let mut reader = Reader::new(bytes);
        let mut msg = reader.read_sequence().unwrap();
        assert_eq!(msg.read_integer().unwrap(), SNMP_VERSION_2C);
        let _community = msg.read_octet_string().unwrap();
        assert_eq!(msg.peek_tag().unwrap(), ber::TAG_RESPONSE);
        let (_, content) = msg.read_tlv().unwrap();
        let mut pdu = Reader::new(content);
        let request_id = pdu.read_integer().unwrap();
        let error_status = pdu.read_integer().unwrap();
        let error_index = pdu.read_integer().unwrap();
        let mut list = pdu.read_sequence().unwrap();
        let mut bindings = Vec::new();
        while !list.is_empty() {
            let mut vb = list.read_sequence().unwrap();
            bindings.push((vb.read_oid().unwrap(), vb.read_value().unwrap()));
        }
        (request_id, error_status, error_index, bindings)
    }

    #[test]
    fn get_returns_identity_scalar_with_echoed_request_id() {
        let core = test_core("public");
        let req = request(
            "public",
            ber::TAG_GET_REQUEST,
            0,
            0,
            &[&[1, 3, 6, 1, 2, 1, 1, 5, 0]],
        );
        let resp = core.handle_datagram(&req, peer()).expect("response");
        let (request_id, status, _, bindings) = decode_response(&resp);
        assert_eq!(request_id, 7);
        assert_eq!(status, 0);
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].1, Value::OctetString(b"edge-1".to_vec()));
    }

    #[test]
    fn get_missing_instance_yields_exception_varbind_not_error() {
        let core = test_core("public");
        let req = request(
            "public",
            ber::TAG_GET_REQUEST,
            0,
            0,
            &[&[1, 3, 6, 1, 2, 1, 1, 5]],
        );
        let resp = core.handle_datagram(&req, peer()).expect("response");
        let (_, status, _, bindings) = decode_response(&resp);
        assert_eq!(status, 0);
        assert_eq!(bindings[0].1, Value::NoSuchInstance);
    }

    #[test]
    fn getnext_walks_and_terminates_with_end_of_mib_view() {
        let core = test_core("public");
        // Start before everything: first entry is sysDescr.0.
        let req = request("public", ber::TAG_GET_NEXT_REQUEST, 0, 0, &[&[1, 3]]);
        let resp = core.handle_datagram(&req, peer()).unwrap();
        let (_, _, _, bindings) = decode_response(&resp);
        assert_eq!(bindings[0].0, Oid::new(&[1, 3, 6, 1, 2, 1, 1, 1, 0]));

        // Walk the full tree, collecting every OID until endOfMibView.
        let mut cursor = Oid::new(&[1, 3]);
        let mut count = 0;
        loop {
            let req = request(
                "public",
                ber::TAG_GET_NEXT_REQUEST,
                0,
                0,
                &[&cursor.0.clone()],
            );
            let resp = core.handle_datagram(&req, peer()).unwrap();
            let (_, _, _, bindings) = decode_response(&resp);
            if bindings[0].1 == Value::EndOfMibView {
                break;
            }
            assert!(bindings[0].0 > cursor);
            cursor = bindings[0].0.clone();
            count += 1;
            assert!(count < 200, "walk did not terminate");
        }
        // 7 system + 4 snmp + 3 identity + 4 listener cols + 4 egress cols.
        assert_eq!(count, 22);
    }

    #[test]
    fn getbulk_equals_repeated_getnext_and_respects_non_repeaters() {
        let core = test_core("public");
        // non-repeaters=1 (sysUpTime fetched once), one repeater walked 5x.
        let req = request(
            "public",
            ber::TAG_GET_BULK_REQUEST,
            1,
            5,
            &[&[1, 3, 6, 1, 2, 1, 1, 3], &[1, 3, 6, 1, 2, 1, 1]],
        );
        let resp = core.handle_datagram(&req, peer()).unwrap();
        let (_, status, _, bulk) = decode_response(&resp);
        assert_eq!(status, 0);
        assert_eq!(bulk.len(), 1 + 5);
        assert_eq!(bulk[0].0, Oid::new(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));

        // The 5 repeated bindings must equal 5 chained GETNEXTs.
        let mut cursor = Oid::new(&[1, 3, 6, 1, 2, 1, 1]);
        for bound in &bulk[1..] {
            let req = request(
                "public",
                ber::TAG_GET_NEXT_REQUEST,
                0,
                0,
                &[&cursor.0.clone()],
            );
            let resp = core.handle_datagram(&req, peer()).unwrap();
            let (_, _, _, single) = decode_response(&resp);
            assert_eq!(single[0], *bound);
            cursor = single[0].0.clone();
        }
    }

    #[test]
    fn getbulk_pads_exhausted_repeaters_with_end_of_mib_view() {
        let core = test_core("public");
        // Start just before the very last subtree so the view exhausts.
        let req = request(
            "public",
            ber::TAG_GET_BULK_REQUEST,
            0,
            4,
            &[&[1, 3, 6, 1, 4, 1, 32473, 61, 3, 1, 4]],
        );
        let resp = core.handle_datagram(&req, peer()).unwrap();
        let (_, _, _, bindings) = decode_response(&resp);
        assert!(!bindings.is_empty());
        assert_eq!(bindings.last().unwrap().1, Value::EndOfMibView);
    }

    #[test]
    fn getbulk_caps_max_repetitions() {
        let core = test_core("public");
        let req = request(
            "public",
            ber::TAG_GET_BULK_REQUEST,
            0,
            1_000_000,
            &[&[1, 3]],
        );
        let resp = core.handle_datagram(&req, peer()).unwrap();
        let (_, status, _, bindings) = decode_response(&resp);
        assert_eq!(status, 0);
        // Whole view (22 entries) + endOfMibView, well under the cap.
        assert!(bindings.len() <= MAX_REPETITIONS_CAP as usize);
        assert_eq!(bindings.last().unwrap().1, Value::EndOfMibView);
    }

    #[test]
    fn set_requests_get_not_writable_and_change_nothing() {
        let core = test_core("public");
        let req = request(
            "public",
            ber::TAG_SET_REQUEST,
            0,
            0,
            &[&[1, 3, 6, 1, 2, 1, 1, 5, 0]],
        );
        let resp = core.handle_datagram(&req, peer()).expect("response");
        let (_, status, index, _) = decode_response(&resp);
        assert_eq!(status, ERR_NOT_WRITABLE);
        assert_eq!(index, 1);

        // Identity unchanged.
        let req = request(
            "public",
            ber::TAG_GET_REQUEST,
            0,
            0,
            &[&[1, 3, 6, 1, 2, 1, 1, 5, 0]],
        );
        let resp = core.handle_datagram(&req, peer()).unwrap();
        let (_, _, _, bindings) = decode_response(&resp);
        assert_eq!(bindings[0].1, Value::OctetString(b"edge-1".to_vec()));
    }

    #[test]
    fn wrong_community_is_silently_dropped_and_counted() {
        let core = test_core("public");
        let req = request(
            "wrong",
            ber::TAG_GET_REQUEST,
            0,
            0,
            &[&[1, 3, 6, 1, 2, 1, 1, 5, 0]],
        );
        assert!(core.handle_datagram(&req, peer()).is_none());
        assert_eq!(core.counters().bad_community_names(), 1);
    }

    #[test]
    fn empty_configured_community_disables_v2c_entirely() {
        // v3-only deployment: the agent validates, but every v2c packet is
        // rejected — even one presenting an empty community string.
        let core = test_core_with(
            "",
            vec![crate::config::SnmpV3UserConfig {
                username: "cacti".to_string(),
                auth_protocol: "sha1".to_string(),
                auth_password: "12345678".to_string(),
                priv_protocol: String::new(),
                priv_password: String::new(),
            }],
        );
        let req = request(
            "",
            ber::TAG_GET_REQUEST,
            0,
            0,
            &[&[1, 3, 6, 1, 2, 1, 1, 5, 0]],
        );
        assert!(core.handle_datagram(&req, peer()).is_none());
        assert_eq!(core.counters().bad_community_names(), 1);
    }

    #[test]
    fn disallowed_source_is_dropped_before_parsing() {
        let core = test_core("public");
        let req = request(
            "public",
            ber::TAG_GET_REQUEST,
            0,
            0,
            &[&[1, 3, 6, 1, 2, 1, 1, 5, 0]],
        );
        let outside: SocketAddr = "203.0.113.9:161".parse().unwrap();
        assert!(core.handle_datagram(&req, outside).is_none());
        // Not a community failure — dropped earlier.
        assert_eq!(core.counters().bad_community_names(), 0);
    }

    #[test]
    fn ipv4_mapped_ipv6_source_matches_ipv4_allowlist() {
        let core = test_core("public");
        let req = request(
            "public",
            ber::TAG_GET_REQUEST,
            0,
            0,
            &[&[1, 3, 6, 1, 2, 1, 1, 5, 0]],
        );
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:34567".parse().unwrap();
        assert!(core.handle_datagram(&req, mapped).is_some());
    }

    #[test]
    fn v1_and_unknown_versions_are_dropped_and_counted() {
        let core = test_core("public");
        for version in [0i64, 5] {
            let mut body = Writer::new();
            body.write_integer(version);
            body.write_octet_string(b"public");
            let msg = Writer::wrap(ber::TAG_SEQUENCE, body).into_bytes();
            assert!(core.handle_datagram(&msg, peer()).is_none());
        }
        assert_eq!(
            core.counters().snapshot().in_bad_versions,
            2,
            "both drops counted"
        );
    }

    #[test]
    fn malformed_packets_are_dropped_and_counted() {
        let core = test_core("public");
        for bad in [
            &[][..],
            &[0xFF, 0x03, 1, 2, 3][..],
            &[0x30, 0x02, 0x02, 0x05][..], // truncated integer
        ] {
            assert!(core.handle_datagram(bad, peer()).is_none());
        }
        // v2c message whose PDU is garbage.
        let mut body = Writer::new();
        body.write_integer(SNMP_VERSION_2C);
        body.write_octet_string(b"public");
        body.write_octet_string(b"not-a-pdu");
        let msg = Writer::wrap(ber::TAG_SEQUENCE, body).into_bytes();
        assert!(core.handle_datagram(&msg, peer()).is_none());
        assert!(core.counters().snapshot().in_asn_parse_errs >= 3);
    }

    #[test]
    fn counters_are_visible_via_snmp_group() {
        let core = test_core("public");
        // Provoke one bad-community drop, then read the counter over SNMP.
        let bad = request("wrong", ber::TAG_GET_REQUEST, 0, 0, &[&[1, 3]]);
        assert!(core.handle_datagram(&bad, peer()).is_none());
        let req = request(
            "public",
            ber::TAG_GET_REQUEST,
            0,
            0,
            &[&[1, 3, 6, 1, 2, 1, 11, 4, 0]],
        );
        let resp = core.handle_datagram(&req, peer()).unwrap();
        let (_, _, _, bindings) = decode_response(&resp);
        assert_eq!(bindings[0].1, Value::Counter32(1));
    }

    #[test]
    fn trap_and_response_pdus_are_ignored() {
        let core = test_core("public");
        let req = request("public", ber::TAG_RESPONSE, 0, 0, &[&[1, 3]]);
        assert!(core.handle_datagram(&req, peer()).is_none());
    }
}
