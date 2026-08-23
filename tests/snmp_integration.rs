//! Socket-level integration tests for the read-only SNMP agent: real UDP
//! datagrams against a bound agent task, exercising the full
//! recv → dispatch → respond loop the binaries run.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rove::config::SnmpConfig;
use rove::snmp::ber::{self, Oid, Reader, Value, Writer};
use rove::snmp::mib::NodeRole;
use rove::snmp::{bind_agent, AgentIdentity};
use rove::stats::TrafficStats;

fn test_config(community: &str, allow: &[&str]) -> SnmpConfig {
    SnmpConfig {
        enable: true,
        listen: "127.0.0.1:0".to_string(),
        community: community.to_string(),
        allow_cidrs: allow.iter().map(|s| s.to_string()).collect(),
        ..SnmpConfig::default()
    }
}

fn identity() -> AgentIdentity {
    AgentIdentity {
        node_id: "itest-edge".to_string(),
        role: NodeRole::Edge,
        version: "0.0.0-test".to_string(),
    }
}

async fn spawn_agent(cfg: SnmpConfig, stats: Arc<TrafficStats>) -> SocketAddr {
    let (addr, serve) = bind_agent(cfg, identity(), stats).await.expect("bind");
    tokio::spawn(serve);
    addr
}

fn encode_request(community: &str, tag: u8, f1: i64, f2: i64, oids: &[&Oid]) -> Vec<u8> {
    let mut list = Writer::new();
    for oid in oids {
        let mut vb = Writer::new();
        vb.write_oid(oid);
        vb.write_null();
        let vb_bytes = Writer::wrap(ber::TAG_SEQUENCE, vb).into_bytes();
        let mut merged = list.into_bytes();
        merged.extend_from_slice(&vb_bytes);
        list = Writer::from_bytes(merged);
    }
    let mut pdu = Writer::new();
    pdu.write_integer(99);
    pdu.write_integer(f1);
    pdu.write_integer(f2);
    let list_bytes = Writer::wrap(ber::TAG_SEQUENCE, list).into_bytes();
    let mut pdu_bytes = pdu.into_bytes();
    pdu_bytes.extend_from_slice(&list_bytes);
    let wrapped_pdu = Writer::wrap(tag, Writer::from_bytes(pdu_bytes)).into_bytes();
    let mut body = Writer::new();
    body.write_integer(1); // v2c
    body.write_octet_string(community.as_bytes());
    let mut body_bytes = body.into_bytes();
    body_bytes.extend_from_slice(&wrapped_pdu);
    Writer::wrap(ber::TAG_SEQUENCE, Writer::from_bytes(body_bytes)).into_bytes()
}

fn decode_bindings(bytes: &[u8]) -> Vec<(Oid, Value)> {
    let mut reader = Reader::new(bytes);
    let mut msg = reader.read_sequence().expect("message seq");
    assert_eq!(msg.read_integer().unwrap(), 1);
    let _community = msg.read_octet_string().unwrap();
    let (tag, content) = msg.read_tlv().unwrap();
    assert_eq!(tag, ber::TAG_RESPONSE);
    let mut pdu = Reader::new(content);
    let _request_id = pdu.read_integer().unwrap();
    assert_eq!(pdu.read_integer().unwrap(), 0, "error-status");
    assert_eq!(pdu.read_integer().unwrap(), 0, "error-index");
    let mut list = pdu.read_sequence().unwrap();
    let mut bindings = Vec::new();
    while !list.is_empty() {
        let mut vb = list.read_sequence().unwrap();
        let oid = vb.read_oid().unwrap();
        let value = vb.read_value().unwrap();
        bindings.push((oid, value));
    }
    bindings
}

async fn exchange(addr: SocketAddr, request: &[u8]) -> Option<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(request, addr).await.unwrap();
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut buf)).await {
        Ok(Ok(len)) => Some(buf[..len].to_vec()),
        _ => None,
    }
}

/// Walk the whole tree with repeated GETNEXT.
async fn getnext_walk(addr: SocketAddr, community: &str) -> Vec<(Oid, Value)> {
    let mut cursor = Oid::new(&[1, 3]);
    let mut entries = Vec::new();
    for _ in 0..200 {
        let request = encode_request(community, ber::TAG_GET_NEXT_REQUEST, 0, 0, &[&cursor]);
        let response = exchange(addr, &request).await.expect("walk response");
        let bindings = decode_bindings(&response);
        let (oid, value) = bindings.into_iter().next().expect("one binding");
        if matches!(value, Value::EndOfMibView) {
            return entries;
        }
        cursor = oid.clone();
        entries.push((oid, value));
    }
    panic!("walk did not terminate within 200 steps");
}

/// Walk the whole tree with repeated GETBULK (the snmpbulkwalk strategy).
async fn getbulk_walk(addr: SocketAddr, community: &str) -> Vec<(Oid, Value)> {
    let mut cursor = Oid::new(&[1, 3]);
    let mut entries = Vec::new();
    for _ in 0..200 {
        let request = encode_request(community, ber::TAG_GET_BULK_REQUEST, 0, 16, &[&cursor]);
        let response = exchange(addr, &request).await.expect("bulk response");
        let bindings = decode_bindings(&response);
        assert!(!bindings.is_empty());
        for (oid, value) in bindings {
            if matches!(value, Value::EndOfMibView) {
                return entries;
            }
            cursor = oid.clone();
            entries.push((oid, value));
        }
    }
    panic!("bulk walk did not terminate within 200 rounds");
}

fn seeded_stats() -> Arc<TrafficStats> {
    let stats = TrafficStats::new();
    stats.register_listener("http-in");
    stats.record_listener_bytes("socks-in", 1_000, 2_000);
    stats.record_egress_bytes("direct", 700, 1_400);
    stats.record_egress_bytes("upstream:hk-1", 300, 600);
    stats
}

#[tokio::test]
async fn getnext_walk_and_getbulk_walk_return_the_same_tree() {
    let addr = spawn_agent(test_config("itest", &["127.0.0.1/32"]), seeded_stats()).await;

    let next_walk = getnext_walk(addr, "itest").await;
    let bulk_walk = getbulk_walk(addr, "itest").await;

    // OID sequences must be identical.
    let next_oids: Vec<String> = next_walk.iter().map(|(o, _)| o.to_string()).collect();
    let bulk_oids: Vec<String> = bulk_walk.iter().map(|(o, _)| o.to_string()).collect();
    assert_eq!(next_oids, bulk_oids);

    // Values in the enterprise subtree are stable between walks (polling
    // itself only mutates sysUpTime and the snmp group counters).
    let base = Oid::new(&[1, 3, 6, 1, 4, 1, 32473, 61]);
    let stable = |walk: &[(Oid, Value)]| -> Vec<(String, Value)> {
        walk.iter()
            .filter(|(oid, _)| oid.starts_with(&base))
            .map(|(oid, v)| (oid.to_string(), v.clone()))
            .collect()
    };
    assert_eq!(stable(&next_walk), stable(&bulk_walk));
    assert!(
        !stable(&next_walk).is_empty(),
        "enterprise subtree must not be empty"
    );

    // Both tables present: 2 listeners x 4 columns + 2 egress x 4 columns.
    assert_eq!(stable(&next_walk).len(), 3 + 8 + 8);
}

#[tokio::test]
async fn byte_counters_are_monotonic_as_traffic_accumulates() {
    let stats = seeded_stats();
    let addr = spawn_agent(test_config("itest", &["127.0.0.1/32"]), stats.clone()).await;

    // listenerBytesUp for "socks-in": column 3, length-prefixed index.
    let mut oid_parts = vec![1u32, 3, 6, 1, 4, 1, 32473, 61, 2, 1, 3, 8];
    oid_parts.extend(b"socks-in".iter().map(|&b| b as u32));
    let oid = Oid::new(&oid_parts);

    let read_counter = |bytes: Vec<u8>| -> u64 {
        let bindings = decode_bindings(&bytes);
        match bindings[0].1 {
            Value::Counter64(v) => v,
            ref other => panic!("expected Counter64, got {other:?}"),
        }
    };

    let request = encode_request("itest", ber::TAG_GET_REQUEST, 0, 0, &[&oid]);
    let first = read_counter(exchange(addr, &request).await.expect("get 1"));
    assert_eq!(first, 1_000);

    stats.record_listener_bytes("socks-in", 234, 0);
    let second = read_counter(exchange(addr, &request).await.expect("get 2"));
    assert_eq!(second, 1_234);
    assert!(second >= first, "counters must be monotonic");
}

#[tokio::test]
async fn source_addresses_outside_the_allowlist_get_no_answer() {
    // Allowlist covers only a TEST-NET address: local requests must vanish.
    let addr = spawn_agent(test_config("itest", &["192.0.2.1/32"]), seeded_stats()).await;

    let oid = Oid::new(&[1, 3, 6, 1, 2, 1, 1, 5, 0]);
    let request = encode_request("itest", ber::TAG_GET_REQUEST, 0, 0, &[&oid]);
    assert!(
        exchange(addr, &request).await.is_none(),
        "blocked source must not receive any bytes"
    );
}

#[tokio::test]
async fn wrong_community_gets_no_answer_over_udp() {
    let addr = spawn_agent(test_config("itest", &["127.0.0.1/32"]), seeded_stats()).await;

    let oid = Oid::new(&[1, 3, 6, 1, 2, 1, 1, 5, 0]);
    let request = encode_request("WRONG", ber::TAG_GET_REQUEST, 0, 0, &[&oid]);
    assert!(exchange(addr, &request).await.is_none());
}

#[tokio::test]
async fn port_conflict_surfaces_as_bind_error_not_panic() {
    let holder = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let taken = holder.local_addr().unwrap();

    let cfg = SnmpConfig {
        listen: taken.to_string(),
        ..test_config("itest", &["127.0.0.1/32"])
    };
    let result = bind_agent(cfg, identity(), TrafficStats::new()).await;
    let err = result.err().expect("bind must fail").to_string();
    assert!(err.contains("bind"), "error should name the bind: {err}");
}

#[tokio::test]
async fn v3_discovery_over_udp_returns_unknown_engine_ids_report() {
    let state = std::env::temp_dir().join(format!(
        "rove-itest-usm-{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let cfg = SnmpConfig {
        state_path: state.to_str().unwrap().to_string(),
        v3_users: vec![rove::config::SnmpV3UserConfig {
            username: "cacti".to_string(),
            auth_protocol: "sha1".to_string(),
            auth_password: "auth-password-1".to_string(),
            priv_protocol: String::new(),
            priv_password: String::new(),
        }],
        ..test_config("", &["127.0.0.1/32"])
    };
    let addr = spawn_agent(cfg, seeded_stats()).await;

    // Minimal discovery message: empty engine ID, noAuthNoPriv, reportable.
    let mut vb = Writer::new();
    vb.write_oid(&Oid::new(&[1, 3, 6, 1, 2, 1, 1, 3, 0]));
    vb.write_null();
    let list = Writer::wrap(
        ber::TAG_SEQUENCE,
        Writer::from_bytes(Writer::wrap(ber::TAG_SEQUENCE, vb).into_bytes()),
    );
    let mut pdu = Writer::new();
    pdu.write_integer(4242);
    pdu.write_integer(0);
    pdu.write_integer(0);
    let mut pdu_bytes = pdu.into_bytes();
    pdu_bytes.extend_from_slice(&list.into_bytes());
    let get = Writer::wrap(ber::TAG_GET_REQUEST, Writer::from_bytes(pdu_bytes)).into_bytes();

    let mut scoped = Writer::new();
    scoped.write_octet_string(b""); // contextEngineID
    scoped.write_octet_string(b""); // contextName
    let mut scoped_bytes = scoped.into_bytes();
    scoped_bytes.extend_from_slice(&get);
    let scoped_tlv = Writer::wrap(ber::TAG_SEQUENCE, Writer::from_bytes(scoped_bytes)).into_bytes();

    let mut global = Writer::new();
    global.write_integer(1); // msgID
    global.write_integer(65507);
    global.write_octet_string(&[0x04]); // reportable, noAuthNoPriv
    global.write_integer(3); // USM
    let mut sec = Writer::new();
    sec.write_octet_string(b"");
    sec.write_integer(0);
    sec.write_integer(0);
    sec.write_octet_string(b"");
    sec.write_octet_string(b"");
    sec.write_octet_string(b"");
    let sec_bytes = Writer::wrap(ber::TAG_SEQUENCE, sec).into_bytes();
    let mut body = Writer::new();
    body.write_integer(3); // version
    let mut body_bytes = body.into_bytes();
    body_bytes.extend_from_slice(&Writer::wrap(ber::TAG_SEQUENCE, global).into_bytes());
    let mut with_sec = Writer::from_bytes(body_bytes);
    with_sec.write_octet_string(&sec_bytes);
    let mut msg_bytes = with_sec.into_bytes();
    msg_bytes.extend_from_slice(&scoped_tlv);
    let request = Writer::wrap(ber::TAG_SEQUENCE, Writer::from_bytes(msg_bytes)).into_bytes();

    let response = exchange(addr, &request).await.expect("discovery report");

    // The response carries our engine ID and the usmStatsUnknownEngineIDs
    // report varbind.
    let mut reader = Reader::new(&response);
    let mut msg = reader.read_sequence().unwrap();
    assert_eq!(msg.read_integer().unwrap(), 3);
    let mut global = msg.read_sequence().unwrap();
    assert_eq!(global.read_integer().unwrap(), 1, "msgID echoed");
    let _ = global.read_integer().unwrap();
    assert_eq!(global.read_octet_string().unwrap(), &[0u8]); // noAuth, not reportable
    assert_eq!(global.read_integer().unwrap(), 3);
    let sec_raw = msg.read_octet_string().unwrap();
    let mut sec = Reader::new(sec_raw).read_sequence().unwrap();
    let engine_id = sec.read_octet_string().unwrap();
    assert_eq!(&engine_id[..5], &[0x80, 0x00, 0x7E, 0xD9, 0x04]);
    assert_eq!(&engine_id[5..], b"itest-edge");
    assert!(sec.read_integer().unwrap() >= 1, "boots");

    let mut scoped = msg.read_sequence().unwrap();
    let _ = scoped.read_octet_string().unwrap();
    let _ = scoped.read_octet_string().unwrap();
    let (tag, content) = scoped.read_tlv().unwrap();
    assert_eq!(tag, ber::TAG_REPORT);
    let mut report = Reader::new(content);
    assert_eq!(report.read_integer().unwrap(), 4242, "request-id echoed");
    assert_eq!(report.read_integer().unwrap(), 0);
    assert_eq!(report.read_integer().unwrap(), 0);
    let mut list = report.read_sequence().unwrap();
    let mut vb = list.read_sequence().unwrap();
    assert_eq!(vb.read_oid().unwrap().to_string(), "1.3.6.1.6.3.15.1.1.4.0");

    let _ = std::fs::remove_file(&state);
}
