use base64::Engine as _;
use rove::diagnostics::{
    DiagnosticEnvelope, DiagnosticEventType, DiagnosticLimits, DiagnosticRegistry,
    DiagnosticSessionSpec,
};
use rove::engine::Engine;
use rove::inbound::{http, socks5, Ctx};
use rove::model::{RawSnapshot, RawUpstream, RawUser, Snapshot};
use rove::util::{read_http_head, read_http_head_with_remainder};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

mod common;
use common::PolicySpec;

const USERNAME: &str = "alice";
const PASSWORD: &str = "secret";
const RATE_LIMIT_BYTES_PER_SEC: u64 = 16 * 1024;
const RATE_LIMIT_TEST_BYTES: usize = 48 * 1024;

#[tokio::test]
async fn http_absolute_get_forwards_origin_form_and_strips_proxy_headers() {
    let (origin_addr, captured, origin_task) = start_http_origin(b"get-ok").await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (mut client, proxy_task) = spawn_http_proxy(engine);
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let request = format!(
        "GET http://{origin_addr}/plain/path?q=1 HTTP/1.1\r\nHost: wrong.example\r\nProxy-Authorization: Basic {token}\r\nProxy-Connection: keep-alive\r\nX-Test: retained\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("get-ok"));

    let captured = captured.await.unwrap();
    assert!(captured
        .head
        .starts_with("GET /plain/path?q=1 HTTP/1.1\r\n"));
    assert!(captured.head.contains(&format!("Host: {origin_addr}\r\n")));
    assert!(captured.head.contains("X-Test: retained\r\n"));
    assert!(captured.head.contains("Connection: close\r\n"));
    assert!(!captured
        .head
        .to_ascii_lowercase()
        .contains("proxy-authorization"));
    assert!(!captured
        .head
        .to_ascii_lowercase()
        .contains("proxy-connection"));
    assert!(captured.body.is_empty());

    assert_task_ok(proxy_task).await;
    origin_task.await.unwrap();
}

#[tokio::test]
async fn http_absolute_post_forwards_body_sent_with_request_head() {
    let (origin_addr, captured, origin_task) = start_http_origin(b"post-ok").await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (mut client, proxy_task) = spawn_http_proxy(engine);
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let body = b"name=rove&mode=plain";
    let mut request = format!(
        "POST http://{origin_addr}/submit HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    client.write_all(&request).await.unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.ends_with("post-ok"));

    let captured = captured.await.unwrap();
    assert!(captured.head.starts_with("POST /submit HTTP/1.1\r\n"));
    assert_eq!(captured.body, body);

    assert_task_ok(proxy_task).await;
    origin_task.await.unwrap();
}

#[tokio::test]
async fn http_absolute_request_requires_auth_before_dialing_origin() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_addr = listener.local_addr().unwrap();
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (mut client, proxy_task) = spawn_http_proxy(engine);
    client
        .write_all(format!("GET http://{origin_addr}/ HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let response = read_http_head(&mut client, 8192).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 407"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "origin must not be dialed before proxy authentication"
    );
    assert_task_ok(proxy_task).await;
}

#[tokio::test]
async fn http_connect_direct_tunnels_bytes() {
    let (target_addr, echo_task) = start_echo_server().await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (mut client, proxy_task) = spawn_http_proxy(engine);

    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let request = format!(
        "CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let response_head = read_http_head(&mut client, 8192).await.unwrap();
    assert!(
        String::from_utf8_lossy(&response_head).starts_with("HTTP/1.1 200"),
        "response was {}",
        String::from_utf8_lossy(&response_head)
    );

    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");

    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();
}

#[tokio::test]
async fn http_connect_observe_sniff_records_host_without_changing_tunnel_bytes() {
    let (target_addr, echo_task) = start_echo_server().await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let (mut client, proxy_task) = spawn_http_proxy_with_observe(engine, logger, stats.clone());
    open_http_tunnel(&mut client, target_addr).await;
    let payload = b"GET /ops HTTP/1.1\r\nHost: Operations.Example\r\n\r\n";

    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();

    let record = records.recv().await.expect("observe access record");
    assert_eq!(record.target_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.requested_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.effective_policy_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.sniffed_host.as_deref(), Some("operations.example"));
    assert_eq!(record.sniff_protocol, Some("http"));
    assert_eq!(record.sniff_outcome, Some("matched"));
    assert_eq!(stats.sniff_rows()[0].matched_total, 1);
}

#[tokio::test]
async fn access_log_file_records_bytes_for_successful_http_tunnel() {
    let (target_addr, echo_task) = start_echo_server().await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });

    let dir = temp_access_log_dir("http-success");
    let cfg = rove::config::AccessLogConfig {
        dir: dir.to_string_lossy().into_owned(),
        channel_capacity: 64,
        ..rove::config::AccessLogConfig::default()
    };
    let access_log = rove::access_log::AccessLogger::spawn(
        &cfg,
        "it-node".to_string(),
        rove::stats::TrafficStats::new(),
    )
    .unwrap();

    let (mut client, proxy_task) = spawn_http_proxy_with_access_log(engine, access_log);

    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let request = format!(
        "CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let response_head = read_http_head(&mut client, 8192).await.unwrap();
    assert!(
        String::from_utf8_lossy(&response_head).starts_with("HTTP/1.1 200"),
        "response was {}",
        String::from_utf8_lossy(&response_head)
    );

    client.write_all(b"ping-ping").await.unwrap();
    let mut echoed = [0u8; 9];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping-ping");

    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();

    let line = read_access_log_line_with_retry(&dir, "\"username\":\"alice\"").await;
    let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed["node_id"], "it-node");
    assert_eq!(parsed["listener"], "test-http");
    assert_eq!(parsed["protocol"], "http");
    assert_eq!(parsed["username"], "alice");
    assert_eq!(parsed["result"], "ok");
    assert!(parsed["bytes_up"].as_u64().unwrap() >= 9);
    assert!(parsed["bytes_down"].as_u64().unwrap() >= 9);
    assert_eq!(parsed["requested_host"], "127.0.0.1");
    assert!(
        parsed.get("sniff_outcome").is_none(),
        "default-disabled sniffing must not emit an outcome: {line}"
    );
    assert!(
        !line.contains(PASSWORD),
        "access log line must never contain the plaintext password: {line}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn socks5_connect_direct_tunnels_bytes() {
    let (target_addr, echo_task) = start_echo_server().await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (mut client, proxy_task) = spawn_socks5_proxy(engine);

    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02]);

    let mut auth = vec![0x01, USERNAME.len() as u8];
    auth.extend_from_slice(USERNAME.as_bytes());
    auth.push(PASSWORD.len() as u8);
    auth.extend_from_slice(PASSWORD.as_bytes());
    client.write_all(&auth).await.unwrap();
    let mut auth_response = [0u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [0x01, 0x00]);

    let SocketAddr::V4(target_addr) = target_addr else {
        panic!("test target must be IPv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target_addr.ip().octets());
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    assert_eq!(reply[1], 0x00);

    client.write_all(b"pong").await.unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"pong");

    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();
}

#[tokio::test]
async fn http_connect_blocked_by_policy_returns_403_without_dialing_out() {
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: vec!["blocked.example".to_string()],
    });
    let (mut client, proxy_task) = spawn_http_proxy(engine);

    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let request = format!(
        "CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let response_head = read_http_head(&mut client, 8192).await.unwrap();
    assert!(
        String::from_utf8_lossy(&response_head).starts_with("HTTP/1.1 403"),
        "response was {}",
        String::from_utf8_lossy(&response_head)
    );

    assert_task_ok(proxy_task).await;
}

#[tokio::test]
async fn diagnostic_session_emits_redacted_policy_event_for_http_block() {
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: vec!["blocked.example".to_string()],
    });
    let (registry, mut events) = diagnostics_registry();
    arm_session(&registry, "diag-http", USERNAME);
    let (mut client, proxy_task) = spawn_http_proxy_with_diagnostics(engine, registry);

    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let request = format!(
        "CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let response_head = read_http_head(&mut client, 8192).await.unwrap();
    assert!(String::from_utf8_lossy(&response_head).starts_with("HTTP/1.1 403"));

    let envelope = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("diagnostic event within timeout")
        .expect("diagnostic event present");
    assert_eq!(envelope.event.event_type, DiagnosticEventType::Policy);
    assert_eq!(envelope.event.username.as_deref(), Some(USERNAME));
    assert_eq!(
        envelope.event.target_host.as_deref(),
        Some("blocked.example")
    );
    assert_eq!(envelope.event.target_port, Some(443));
    assert_eq!(envelope.event.status, "error");

    // The serialized event must never leak the client's password.
    let raw = serde_json::to_string(&envelope.event).unwrap();
    assert!(!raw.contains(PASSWORD), "event leaked secret: {raw}");

    assert_task_ok(proxy_task).await;
}

#[tokio::test]
async fn diagnostic_session_emits_splice_event_for_socks5_success() {
    let (target_addr, echo_task) = start_echo_server().await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (registry, mut events) = diagnostics_registry();
    arm_session(&registry, "diag-socks", USERNAME);
    let (mut client, proxy_task) = spawn_socks5_proxy_with_diagnostics(engine, registry);

    let reply = establish_socks5_tunnel(&mut client, target_addr).await;
    assert_eq!(reply[1], 0x00);
    client.write_all(b"pong").await.unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"pong");
    client.shutdown().await.unwrap();

    let envelope = tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("diagnostic event within timeout")
        .expect("diagnostic event present");
    assert_eq!(envelope.event.event_type, DiagnosticEventType::Splice);
    assert_eq!(envelope.event.protocol, "socks5");
    assert_eq!(envelope.event.status, "ok");
    assert_eq!(envelope.event.username.as_deref(), Some(USERNAME));

    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();
}

#[tokio::test]
async fn no_diagnostic_events_without_active_session() {
    let (target_addr, echo_task) = start_echo_server().await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    // Registry is wired but no session is armed.
    let (registry, mut events) = diagnostics_registry();
    let (mut client, proxy_task) = spawn_http_proxy_with_diagnostics(engine, registry);

    establish_http_tunnel(&mut client, target_addr).await;
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    client.shutdown().await.unwrap();

    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();
    assert!(
        events.try_recv().is_err(),
        "no events should be published without an armed session"
    );
}
#[tokio::test]
async fn http_connect_max_connections_rejects_second_tunnel_then_releases() {
    let engine = engine_with_limits(
        0,
        0,
        1,
        PolicySpec {
            egress: None,
            default_egress: None,
            routed: Vec::new(),
            blocked: Vec::new(),
        },
    );

    let (first_target_addr, first_echo_task) = start_echo_server().await;
    let (mut first_client, first_proxy_task) = spawn_http_proxy(engine.clone());
    establish_http_tunnel(&mut first_client, first_target_addr).await;

    let (mut second_client, second_proxy_task) = spawn_http_proxy(engine.clone());
    let response_head = open_http_tunnel(&mut second_client, first_target_addr).await;
    assert!(
        String::from_utf8_lossy(&response_head).starts_with("HTTP/1.1 429"),
        "response was {}",
        String::from_utf8_lossy(&response_head)
    );
    assert_task_ok(second_proxy_task).await;

    first_client.shutdown().await.unwrap();
    assert_task_ok(first_proxy_task).await;
    first_echo_task.await.unwrap();

    let (third_target_addr, third_echo_task) = start_echo_server().await;
    let (mut third_client, third_proxy_task) = spawn_http_proxy(engine);
    establish_http_tunnel(&mut third_client, third_target_addr).await;
    third_client.shutdown().await.unwrap();
    assert_task_ok(third_proxy_task).await;
    third_echo_task.await.unwrap();
}

#[tokio::test]
async fn socks5_max_connections_rejects_second_tunnel_then_releases() {
    let engine = engine_with_limits(
        0,
        0,
        1,
        PolicySpec {
            egress: None,
            default_egress: None,
            routed: Vec::new(),
            blocked: Vec::new(),
        },
    );

    let (first_target_addr, first_echo_task) = start_echo_server().await;
    let (mut first_client, first_proxy_task) = spawn_socks5_proxy(engine.clone());
    let first_reply = establish_socks5_tunnel(&mut first_client, first_target_addr).await;
    assert_eq!(first_reply[1], 0x00);

    let (mut second_client, second_proxy_task) = spawn_socks5_proxy(engine.clone());
    let second_reply = establish_socks5_tunnel(&mut second_client, first_target_addr).await;
    assert_eq!(second_reply[1], 0x02);
    assert_task_ok(second_proxy_task).await;

    first_client.shutdown().await.unwrap();
    assert_task_ok(first_proxy_task).await;
    first_echo_task.await.unwrap();

    let (third_target_addr, third_echo_task) = start_echo_server().await;
    let (mut third_client, third_proxy_task) = spawn_socks5_proxy(engine);
    let third_reply = establish_socks5_tunnel(&mut third_client, third_target_addr).await;
    assert_eq!(third_reply[1], 0x00);
    third_client.shutdown().await.unwrap();
    assert_task_ok(third_proxy_task).await;
    third_echo_task.await.unwrap();
}

#[tokio::test]
async fn http_connect_down_rate_throttles_target_to_client_bytes() {
    let (target_addr, target_task) = start_sender_server(RATE_LIMIT_TEST_BYTES).await;
    let engine = engine_with_rates(
        0,
        RATE_LIMIT_BYTES_PER_SEC,
        PolicySpec {
            egress: None,
            default_egress: None,
            routed: Vec::new(),
            blocked: Vec::new(),
        },
    );
    let (mut client, proxy_task) = spawn_http_proxy(engine);

    establish_http_tunnel(&mut client, target_addr).await;

    let started = Instant::now();
    let mut received = vec![0u8; RATE_LIMIT_TEST_BYTES];
    client.read_exact(&mut received).await.unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(1500),
        "down_rate limit completed too quickly: {elapsed:?}"
    );
    assert_eq!(received, vec![b'x'; RATE_LIMIT_TEST_BYTES]);

    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    target_task.await.unwrap();
}

#[tokio::test]
async fn http_connect_up_rate_throttles_client_to_target_bytes() {
    let (target_addr, target_task) = start_receiver_server(RATE_LIMIT_TEST_BYTES).await;
    let engine = engine_with_rates(
        RATE_LIMIT_BYTES_PER_SEC,
        0,
        PolicySpec {
            egress: None,
            default_egress: None,
            routed: Vec::new(),
            blocked: Vec::new(),
        },
    );
    let (mut client, proxy_task) = spawn_http_proxy(engine);

    establish_http_tunnel(&mut client, target_addr).await;

    let payload = vec![b'y'; RATE_LIMIT_TEST_BYTES];
    let started = Instant::now();
    client.write_all(&payload).await.unwrap();
    let mut ack = [0u8; 2];
    client.read_exact(&mut ack).await.unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed >= Duration::from_millis(1500),
        "up_rate limit completed too quickly: {elapsed:?}"
    );
    assert_eq!(&ack, b"ok");

    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    target_task.await.unwrap();
}

fn engine_with_policy(policy: PolicySpec) -> Arc<Engine> {
    engine_with_rates(0, 0, policy)
}

fn engine_with_rates(up_rate: u64, down_rate: u64, policy: PolicySpec) -> Arc<Engine> {
    engine_with_limits(up_rate, down_rate, 0, policy)
}

fn engine_with_limits(
    up_rate: u64,
    down_rate: u64,
    max_connections: usize,
    policy: PolicySpec,
) -> Arc<Engine> {
    let mut users = HashMap::new();
    users.insert(
        USERNAME.to_string(),
        RawUser {
            password: PASSWORD.to_string(),
            expire: None,
            up_rate,
            down_rate,
            max_connections,
            policy: "default".to_string(),
            frontends: Default::default(),
        },
    );

    let (routing_policies, egresses) = policy.into_tables("default");

    let engine = Engine::new();
    let snapshot = Snapshot::compile(
        RawSnapshot {
            version: 1,
            users,
            routing_policies,
            egresses,
            ..Default::default()
        },
        "node-1",
    )
    .unwrap();
    engine.replace(snapshot);
    engine
}

async fn establish_http_tunnel(client: &mut DuplexStream, target_addr: SocketAddr) {
    let response_head = open_http_tunnel(client, target_addr).await;
    assert!(
        String::from_utf8_lossy(&response_head).starts_with("HTTP/1.1 200"),
        "response was {}",
        String::from_utf8_lossy(&response_head)
    );
}

async fn open_http_tunnel(client: &mut DuplexStream, target_addr: SocketAddr) -> Vec<u8> {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let request = format!(
        "CONNECT {target_addr} HTTP/1.1\r\nHost: {target_addr}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();

    read_http_head(client, 8192).await.unwrap()
}

async fn establish_socks5_tunnel(client: &mut DuplexStream, target_addr: SocketAddr) -> [u8; 10] {
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02]);

    let mut auth = vec![0x01, USERNAME.len() as u8];
    auth.extend_from_slice(USERNAME.as_bytes());
    auth.push(PASSWORD.len() as u8);
    auth.extend_from_slice(PASSWORD.as_bytes());
    client.write_all(&auth).await.unwrap();
    let mut auth_response = [0u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [0x01, 0x00]);

    let SocketAddr::V4(target_addr) = target_addr else {
        panic!("test target must be IPv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target_addr.ip().octets());
    request.extend_from_slice(&target_addr.port().to_be_bytes());
    client.write_all(&request).await.unwrap();

    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 0x05);
    reply
}

#[tokio::test]
async fn socks5_connect_observe_sniff_records_host_without_changing_tunnel_bytes() {
    let (target_addr, echo_task) = start_echo_server().await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let (mut client, proxy_task) = spawn_socks5_proxy_with_observe(engine, logger, stats.clone());
    establish_socks5_tunnel(&mut client, target_addr).await;
    let payload = b"GET /mobile HTTP/1.1\r\nHost: Mobile.Example\r\n\r\n";

    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();

    let record = records.recv().await.expect("observe access record");
    assert_eq!(record.target_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.requested_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.sniffed_host.as_deref(), Some("mobile.example"));
    assert_eq!(record.sniff_protocol, Some("http"));
    assert_eq!(record.sniff_outcome, Some("matched"));
    assert_eq!(stats.sniff_rows()[0].matched_total, 1);
}

#[tokio::test]
async fn socks5_connect_observe_sniff_forwards_unsupported_payload_and_counts_outcome() {
    let (target_addr, echo_task) = start_echo_server().await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let (mut client, proxy_task) = spawn_socks5_proxy_with_observe(engine, logger, stats.clone());
    establish_socks5_tunnel(&mut client, target_addr).await;
    let payload = b"\x01\x02\x03\x04opaque";

    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();

    let record = records.recv().await.expect("observe access record");
    assert_eq!(record.sniffed_host, None);
    assert_eq!(record.sniff_protocol, None);
    assert_eq!(record.sniff_outcome, Some("unsupported"));
    assert_eq!(stats.sniff_rows()[0].unsupported_total, 1);
}

#[tokio::test]
async fn http_connect_route_sniffed_block_prevents_requested_ip_dial() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: vec!["blocked.example".to_string()],
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let (mut client, proxy_task) = spawn_http_proxy_with_route(engine, logger, stats.clone());
    establish_http_tunnel(&mut client, target_addr).await;
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: Blocked.Example\r\n\r\n")
        .await
        .unwrap();

    let record = tokio::time::timeout(Duration::from_secs(2), records.recv())
        .await
        .expect("route block access record timed out")
        .expect("route block access record");
    assert_eq!(record.target_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.requested_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.sniffed_host.as_deref(), Some("blocked.example"));
    assert_eq!(
        record.effective_policy_host.as_deref(),
        Some("blocked.example")
    );
    assert_eq!(record.decision.as_deref(), Some("block"));
    assert_eq!(record.failure_stage.as_deref(), Some("policy"));
    assert_eq!(record.snapshot_version, 1);
    assert_eq!(stats.sniff_rows()[0].matched_total, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), target.accept())
            .await
            .is_err(),
        "requested IP must not be dialed after sniffed block"
    );
    let _ = client.shutdown().await;
    assert_task_ok(proxy_task).await;
}

#[tokio::test]
async fn http_connect_route_unmatched_sniff_replays_captured_prefix_to_requested_ip() {
    let (target_addr, echo_task) = start_echo_server().await;
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let (mut client, proxy_task) = spawn_http_proxy_with_route(engine, logger, stats.clone());
    establish_http_tunnel(&mut client, target_addr).await;
    let payload = b"GET /route HTTP/1.1\r\nHost: Route.Example\r\n\r\nbody";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();

    let record = records.recv().await.expect("route access record");
    assert_eq!(record.requested_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.sniffed_host.as_deref(), Some("route.example"));
    assert_eq!(record.effective_policy_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.decision.as_deref(), Some("direct"));
    assert_eq!(record.result, "ok");
    assert_eq!(stats.sniff_rows()[0].matched_total, 1);
}

#[tokio::test]
async fn http_connect_route_sniffed_proxy_selects_egress_but_dials_requested_ip() {
    let (echo_addr, echo_task) = start_echo_server().await;
    let (upstream, upstream_target) = start_http_connect_upstream().await;
    let engine = engine_with_policy(PolicySpec {
        egress: Some(RawUpstream {
            kind: "http".to_string(),
            addr: upstream.clone(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        }),
        default_egress: None,
        routed: vec!["route.example".to_string()],
        blocked: Vec::new(),
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let (mut client, proxy_task) = spawn_http_proxy_with_route(engine, logger, stats);
    establish_http_tunnel(&mut client, echo_addr).await;
    let payload = b"GET /proxy HTTP/1.1\r\nHost: Route.Example\r\n\r\n";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    let dialed = tokio::time::timeout(Duration::from_secs(2), upstream_target)
        .await
        .expect("upstream target capture timed out")
        .expect("upstream target capture");
    assert_eq!(dialed, echo_addr.to_string());
    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();

    let record = records.recv().await.expect("proxied route access record");
    assert_eq!(record.sniffed_host.as_deref(), Some("route.example"));
    assert_eq!(
        record.effective_policy_host.as_deref(),
        Some("route.example")
    );
    assert_eq!(
        record.decision.as_deref(),
        Some(format!("upstream:{upstream}").as_str())
    );
    assert_eq!(record.target_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.snapshot_version, 1);
}

#[tokio::test]
async fn socks5_connect_route_sniffed_block_prevents_requested_ip_dial() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: vec!["blocked.example".to_string()],
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let (mut client, proxy_task) = spawn_socks5_proxy_with_route(engine, logger, stats.clone());
    let reply = establish_socks5_tunnel(&mut client, target_addr).await;
    assert_eq!(reply[1], 0x00);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: Blocked.Example\r\n\r\n")
        .await
        .unwrap();

    let record = tokio::time::timeout(Duration::from_secs(2), records.recv())
        .await
        .expect("socks route block access record timed out")
        .expect("socks route block access record");
    assert_eq!(record.sniffed_host.as_deref(), Some("blocked.example"));
    assert_eq!(
        record.effective_policy_host.as_deref(),
        Some("blocked.example")
    );
    assert_eq!(record.decision.as_deref(), Some("block"));
    assert_eq!(record.failure_stage.as_deref(), Some("policy"));
    assert_eq!(stats.sniff_rows()[0].matched_total, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), target.accept())
            .await
            .is_err(),
        "requested IP must not be dialed after sniffed block"
    );
    let _ = client.shutdown().await;
    assert_task_ok(proxy_task).await;
}

#[tokio::test]
async fn socks5_connect_route_sniffed_proxy_selects_egress_but_dials_requested_ip() {
    let (echo_addr, echo_task) = start_echo_server().await;
    let (upstream, upstream_target) = start_http_connect_upstream().await;
    let engine = engine_with_policy(PolicySpec {
        egress: Some(RawUpstream {
            kind: "http".to_string(),
            addr: upstream.clone(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        }),
        default_egress: None,
        routed: vec!["route.example".to_string()],
        blocked: Vec::new(),
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let (mut client, proxy_task) = spawn_socks5_proxy_with_route(engine, logger, stats);
    let reply = establish_socks5_tunnel(&mut client, echo_addr).await;
    assert_eq!(reply[1], 0x00);
    let payload = b"GET /proxy HTTP/1.1\r\nHost: Route.Example\r\n\r\n";
    client.write_all(payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    let dialed = tokio::time::timeout(Duration::from_secs(2), upstream_target)
        .await
        .expect("upstream target capture timed out")
        .expect("upstream target capture");
    assert_eq!(dialed, echo_addr.to_string());
    client.shutdown().await.unwrap();
    assert_task_ok(proxy_task).await;
    echo_task.await.unwrap();

    let record = records.recv().await.expect("socks proxied route record");
    assert_eq!(record.sniffed_host.as_deref(), Some("route.example"));
    assert_eq!(
        record.effective_policy_host.as_deref(),
        Some("route.example")
    );
    assert_eq!(
        record.decision.as_deref(),
        Some(format!("upstream:{upstream}").as_str())
    );
    assert_eq!(record.target_host.as_deref(), Some("127.0.0.1"));
}

#[tokio::test]
async fn http_connect_unresolvable_host_records_dns_stage() {
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let (mut client, proxy_task) = spawn_http_proxy_with_access_log(engine, logger);
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    client
        .write_all(
            format!(
                "CONNECT no-such-host.invalid:443 HTTP/1.1\r\nHost: no-such-host.invalid:443\r\nProxy-Authorization: Basic {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_http_head(&mut client, 8192).await.unwrap();
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 502"),
        "response was {}",
        String::from_utf8_lossy(&head)
    );
    let record = tokio::time::timeout(Duration::from_secs(5), records.recv())
        .await
        .expect("dns stage record timed out")
        .expect("dns stage record");
    assert_eq!(record.failure_stage.as_deref(), Some("dns"));
    assert_eq!(record.target_host.as_deref(), Some("no-such-host.invalid"));
    let _ = client.shutdown().await;
    assert_task_ok(proxy_task).await;
}

#[tokio::test]
async fn http_connect_refused_port_records_dial_stage() {
    let engine = engine_with_policy(PolicySpec {
        egress: None,
        default_egress: None,
        routed: Vec::new(),
        blocked: Vec::new(),
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let (mut client, proxy_task) = spawn_http_proxy_with_access_log(engine, logger);
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    client
        .write_all(
            format!(
                "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_http_head(&mut client, 8192).await.unwrap();
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 502"));
    let record = tokio::time::timeout(Duration::from_secs(2), records.recv())
        .await
        .expect("dial stage record timed out")
        .expect("dial stage record");
    assert_eq!(record.failure_stage.as_deref(), Some("dial"));
    assert_eq!(record.target_host.as_deref(), Some("127.0.0.1"));
    let _ = client.shutdown().await;
    assert_task_ok(proxy_task).await;
}

#[tokio::test]
async fn http_connect_upstream_tls_handshake_failure_records_tls_stage() {
    rove::tls::init_crypto();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hop = listener.local_addr().unwrap();
    let hop_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 64];
            let _ = socket.read(&mut buf).await;
        }
    });
    let engine = engine_with_policy(PolicySpec {
        egress: Some(RawUpstream {
            kind: "http".to_string(),
            addr: hop.to_string(),
            username: None,
            password: None,
            tls: true,
            skip_cert_verify: true,
        }),
        default_egress: None,
        routed: vec!["example.com".to_string()],
        blocked: Vec::new(),
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let (mut client, proxy_task) = spawn_http_proxy_with_access_log(engine, logger);
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    client
        .write_all(
            format!(
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {token}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let head = read_http_head(&mut client, 8192).await.unwrap();
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 502"));
    let record = tokio::time::timeout(Duration::from_secs(2), records.recv())
        .await
        .expect("tls stage record timed out")
        .expect("tls stage record");
    assert_eq!(record.failure_stage.as_deref(), Some("tls"));
    assert_eq!(
        record.decision.as_deref(),
        Some(format!("upstream:{hop}").as_str())
    );
    let _ = client.shutdown().await;
    assert_task_ok(proxy_task).await;
    let _ = hop_task.await;
}

fn test_peer() -> SocketAddr {
    "203.0.113.40:44444".parse().unwrap()
}

fn spawn_http_proxy(engine: Arc<Engine>) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-http".to_string(),
        sniff: rove::config::SniffConfig::default(),
        tracer: None,
        diagnostics: None,
        access_log: None,
        stats: rove::stats::TrafficStats::new(),
        egress: rove::outbound::EgressContext::default(),
    });
    let task = tokio::spawn(http::serve(server, ctx, test_peer()));
    (client, task)
}

fn spawn_socks5_proxy(engine: Arc<Engine>) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-socks5".to_string(),
        sniff: rove::config::SniffConfig::default(),
        tracer: None,
        diagnostics: None,
        access_log: None,
        stats: rove::stats::TrafficStats::new(),
        egress: rove::outbound::EgressContext::default(),
    });
    let task = tokio::spawn(socks5::serve(server, ctx, test_peer(), None));
    (client, task)
}

fn observe_sniff_config() -> rove::config::SniffConfig {
    rove::config::SniffConfig {
        enabled: true,
        ..rove::config::SniffConfig::default()
    }
}

fn route_sniff_config() -> rove::config::SniffConfig {
    rove::config::SniffConfig {
        enabled: true,
        mode: rove::config::SniffMode::Route,
        ..rove::config::SniffConfig::default()
    }
}

fn spawn_http_proxy_with_observe(
    engine: Arc<Engine>,
    access_log: Arc<rove::access_log::AccessLogger>,
    stats: Arc<rove::stats::TrafficStats>,
) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-http-observe".to_string(),
        sniff: observe_sniff_config(),
        tracer: None,
        diagnostics: None,
        access_log: Some(access_log),
        stats,
        egress: rove::outbound::EgressContext::default(),
    });
    let task = tokio::spawn(http::serve(server, ctx, test_peer()));
    (client, task)
}

fn spawn_http_proxy_with_route(
    engine: Arc<Engine>,
    access_log: Arc<rove::access_log::AccessLogger>,
    stats: Arc<rove::stats::TrafficStats>,
) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-http-route".to_string(),
        sniff: route_sniff_config(),
        tracer: None,
        diagnostics: None,
        access_log: Some(access_log),
        stats,
        egress: rove::outbound::EgressContext::default(),
    });
    let task = tokio::spawn(http::serve(server, ctx, test_peer()));
    (client, task)
}

fn spawn_socks5_proxy_with_route(
    engine: Arc<Engine>,
    access_log: Arc<rove::access_log::AccessLogger>,
    stats: Arc<rove::stats::TrafficStats>,
) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-socks5-route".to_string(),
        sniff: route_sniff_config(),
        tracer: None,
        diagnostics: None,
        access_log: Some(access_log),
        stats,
        egress: rove::outbound::EgressContext::default(),
    });
    let task = tokio::spawn(socks5::serve(server, ctx, test_peer(), None));
    (client, task)
}

fn spawn_socks5_proxy_with_observe(
    engine: Arc<Engine>,
    access_log: Arc<rove::access_log::AccessLogger>,
    stats: Arc<rove::stats::TrafficStats>,
) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-socks5-observe".to_string(),
        sniff: observe_sniff_config(),
        tracer: None,
        diagnostics: None,
        access_log: Some(access_log),
        stats,
        egress: rove::outbound::EgressContext::default(),
    });
    let task = tokio::spawn(socks5::serve(server, ctx, test_peer(), None));
    (client, task)
}

fn diagnostics_registry() -> (Arc<DiagnosticRegistry>, mpsc::Receiver<DiagnosticEnvelope>) {
    let (tx, rx) = mpsc::channel(16);
    let limits = DiagnosticLimits {
        default_ttl: Duration::from_secs(30),
        max_ttl: Duration::from_secs(300),
        max_sessions: 8,
        max_sessions_per_user: 4,
    };
    let registry = Arc::new(DiagnosticRegistry::new("test-node".to_string(), limits, tx));
    (registry, rx)
}

fn arm_session(registry: &Arc<DiagnosticRegistry>, request_id: &str, username: &str) {
    registry
        .start(DiagnosticSessionSpec {
            request_id: request_id.to_string(),
            reply_topic: format!("rove/replies/{request_id}"),
            username: username.to_string(),
            target_host: None,
            target_port: None,
            protocol: None,
            listener: None,
            event_types: DiagnosticEventType::PER_CONNECTION.into_iter().collect(),
            ttl: Duration::from_secs(30),
        })
        .expect("diagnostic session arms");
}

fn spawn_http_proxy_with_diagnostics(
    engine: Arc<Engine>,
    diagnostics: Arc<DiagnosticRegistry>,
) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-http".to_string(),
        sniff: rove::config::SniffConfig::default(),
        tracer: None,
        diagnostics: Some(diagnostics),
        access_log: None,
        stats: rove::stats::TrafficStats::new(),
        egress: rove::outbound::EgressContext::default(),
    });
    let task = tokio::spawn(http::serve(server, ctx, test_peer()));
    (client, task)
}

fn spawn_socks5_proxy_with_diagnostics(
    engine: Arc<Engine>,
    diagnostics: Arc<DiagnosticRegistry>,
) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-socks5".to_string(),
        sniff: rove::config::SniffConfig::default(),
        tracer: None,
        diagnostics: Some(diagnostics),
        access_log: None,
        stats: rove::stats::TrafficStats::new(),
        egress: rove::outbound::EgressContext::default(),
    });
    let task = tokio::spawn(socks5::serve(server, ctx, test_peer(), None));
    (client, task)
}

fn spawn_http_proxy_with_access_log(
    engine: Arc<Engine>,
    access_log: Arc<rove::access_log::AccessLogger>,
) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-http".to_string(),
        sniff: rove::config::SniffConfig::default(),
        tracer: None,
        diagnostics: None,
        access_log: Some(access_log),
        stats: rove::stats::TrafficStats::new(),
        egress: rove::outbound::EgressContext::default(),
    });
    let task = tokio::spawn(http::serve(server, ctx, test_peer()));
    (client, task)
}

fn temp_access_log_dir(name: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("rove-it-access-log-{name}-{nanos}"))
}

async fn read_access_log_line_with_retry(dir: &std::path::Path, needle: &str) -> String {
    for _ in 0..100 {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if let Some(line) = content.lines().find(|l| l.contains(needle)) {
                        return line.to_string();
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("no access log line containing {needle:?} found after retries in {dir:?}");
}

async fn start_http_connect_upstream() -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (target_tx, target_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let head = read_http_head(&mut client, 8192).await.unwrap();
        let head = String::from_utf8(head).unwrap();
        let authority = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("CONNECT authority")
            .to_string();
        let mut target = tokio::net::TcpStream::connect(&authority).await.unwrap();
        let _ = target_tx.send(authority);
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
    });
    (address, target_rx)
}

async fn start_echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        loop {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            socket.write_all(&buf[..n]).await.unwrap();
        }
    });
    (addr, task)
}

struct CapturedHttpRequest {
    head: String,
    body: Vec<u8>,
}

async fn start_http_origin(
    response_body: &'static [u8],
) -> (
    SocketAddr,
    oneshot::Receiver<CapturedHttpRequest>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (captured_tx, captured_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (head, remainder) = read_http_head_with_remainder(&mut socket, 8192)
            .await
            .unwrap();
        let head_text = String::from_utf8(head).unwrap();
        let content_length = head_text
            .split("\r\n")
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut body = remainder;
        if body.len() < content_length {
            let initial = body.len();
            body.resize(content_length, 0);
            socket.read_exact(&mut body[initial..]).await.unwrap();
        }
        assert_eq!(body.len(), content_length);
        captured_tx
            .send(CapturedHttpRequest {
                head: head_text,
                body,
            })
            .ok();
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response_body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(response_body).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    (addr, captured_rx, task)
}

async fn start_sender_server(bytes: usize) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(&vec![b'x'; bytes]).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    (addr, task)
}

async fn start_receiver_server(bytes: usize) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = vec![0u8; bytes];
        socket.read_exact(&mut received).await.unwrap();
        assert_eq!(received, vec![b'y'; bytes]);
        socket.write_all(b"ok").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    (addr, task)
}

async fn assert_task_ok(task: JoinHandle<anyhow::Result<()>>) {
    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("proxy task timed out")
        .expect("proxy task panicked");
    result.expect("proxy task failed");
}
