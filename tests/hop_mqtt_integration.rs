//! Process E2E for `rove-hop` MQTT egress doctor.
//! Fake broker + plaintext TCP target: TLS fails, TCP succeeds.

#![cfg(unix)]

use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS};
use std::collections::HashMap;
use std::net::TcpListener as StdListener;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const HOP_ID: &str = "rove-hop-jp";
const PROXY_PASSWORD: &str = "egress-secret";
const MQTT_PASSWORD: &str = "mqtt-hop-pass";

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[derive(Clone)]
struct Publish {
    topic: String,
    payload: Vec<u8>,
}

struct Broker {
    subs: HashMap<String, Vec<mpsc::UnboundedSender<Publish>>>,
}

impl Broker {
    fn new() -> Self {
        Broker {
            subs: HashMap::new(),
        }
    }
}

#[tokio::test]
async fn hop_mqtt_doctor_reports_tls_failure_after_tcp_ok_without_leaking_secrets() {
    let broker_port = start_broker().await;
    let target_port = start_plaintext_target().await;
    let socks5_port = pick_free_port();
    let _hop = start_hop(broker_port, socks5_port);

    let mut options = MqttOptions::new("hop-doctor-e2e", "127.0.0.1", broker_port);
    options.set_keep_alive(Duration::from_secs(5));
    options.set_clean_session(true);
    let (client, mut eventloop) = AsyncClient::new(options, 16);
    client
        .subscribe("rove/replies/#", QoS::AtLeastOnce)
        .await
        .unwrap();

    let pump = tokio::spawn(async move {
        let mut replies = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(400), eventloop.poll()).await {
                Ok(Ok(Event::Incoming(Incoming::Publish(publish)))) => {
                    if publish.topic.starts_with("rove/replies/") {
                        replies.push(publish.payload.to_vec());
                        break;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(_) => {}
            }
        }
        replies
    });

    tokio::time::sleep(Duration::from_secs(2)).await;
    let command = format!(
        r#"{{
            "command":"hop_egress_doctor",
            "request_id":"doc-e2e",
            "reply_topic":"rove/replies/hop-doctor-doc-e2e",
            "data":{{"target":"127.0.0.1:{target_port}","timeout_ms":2000}}
        }}"#
    );
    client
        .publish(
            format!("rove/hop/{HOP_ID}/doctor"),
            QoS::AtLeastOnce,
            false,
            command,
        )
        .await
        .unwrap();

    let replies = pump.await.expect("controller eventloop");
    assert_eq!(replies.len(), 1, "expected one hop doctor reply");
    let body = String::from_utf8(replies[0].clone()).expect("utf8 reply");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json reply");
    assert_eq!(parsed["request_id"], "doc-e2e");
    assert_eq!(parsed["hop_id"], HOP_ID);
    assert_eq!(parsed["event"], "hop_egress_doctor");
    assert_eq!(parsed["kind"], "egress_diagnostic");
    assert_eq!(parsed["result"], "failed");
    assert_eq!(
        parsed["tcp"]["status"], "ok",
        "plaintext listener must accept TCP: {body}"
    );
    assert_eq!(
        parsed["tls"]["status"], "failed",
        "plaintext listener must fail TLS: {body}"
    );
    assert!(
        parsed.get("dns").is_some(),
        "layered report missing dns: {body}"
    );
    assert!(
        parsed.get("route").is_some(),
        "layered report missing route: {body}"
    );
    assert!(
        parsed.get("http").is_some(),
        "layered report missing http: {body}"
    );
    assert_eq!(parsed["trace"]["status"], "skipped");
    assert!(
        !body.contains(PROXY_PASSWORD),
        "reply must not contain the hop proxy password: {body}"
    );
    assert!(
        !body.contains(MQTT_PASSWORD),
        "reply must not contain the mqtt password: {body}"
    );
}

#[tokio::test]
async fn hop_mqtt_doctor_rejects_missing_target_without_running_probe() {
    let broker_port = start_broker().await;
    let socks5_port = pick_free_port();
    let _hop = start_hop(broker_port, socks5_port);

    let mut options = MqttOptions::new("hop-doctor-bad", "127.0.0.1", broker_port);
    options.set_keep_alive(Duration::from_secs(5));
    options.set_clean_session(true);
    let (client, mut eventloop) = AsyncClient::new(options, 16);
    client
        .subscribe("rove/replies/#", QoS::AtLeastOnce)
        .await
        .unwrap();

    let pump = tokio::spawn(async move {
        let mut replies = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(400), eventloop.poll()).await {
                Ok(Ok(Event::Incoming(Incoming::Publish(publish)))) => {
                    if publish.topic.starts_with("rove/replies/") {
                        replies.push(publish.payload.to_vec());
                        break;
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(_) => {}
            }
        }
        replies
    });

    tokio::time::sleep(Duration::from_secs(2)).await;
    client
        .publish(
            format!("rove/hop/{HOP_ID}/doctor"),
            QoS::AtLeastOnce,
            false,
            br#"{
                "request_id":"doc-missing",
                "reply_topic":"rove/replies/hop-doctor-missing",
                "data":{}
            }"#,
        )
        .await
        .unwrap();

    let replies = pump.await.expect("controller eventloop");
    assert_eq!(replies.len(), 1);
    let body = String::from_utf8(replies[0].clone()).expect("utf8 reply");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json reply");
    assert_eq!(parsed["status"], "bad_request");
    assert!(parsed["message"]
        .as_str()
        .unwrap_or_default()
        .contains("target"));
    assert!(parsed.get("tcp").is_none());
    assert!(!body.contains(MQTT_PASSWORD));
}

async fn start_plaintext_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            });
        }
    });
    port
}

fn start_hop(broker_port: u16, socks5_port: u16) -> ChildGuard {
    let mut last = String::new();
    for attempt in 0..8 {
        match try_start_hop(broker_port, socks5_port, attempt) {
            Ok(hop) => return hop,
            Err(error) => last = error,
        }
    }
    panic!("rove-hop mqtt doctor failed to start after retries: {last}");
}

fn try_start_hop(broker_port: u16, socks5_port: u16, attempt: u32) -> Result<ChildGuard, String> {
    let workdir = std::env::temp_dir().join(format!(
        "rove-hop-mqtt-it-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
        attempt
    ));
    std::fs::create_dir_all(&workdir).map_err(|e| e.to_string())?;
    let stderr_path = workdir.join("rove-hop.err");
    let stderr = std::fs::File::create(&stderr_path).map_err(|e| e.to_string())?;
    let child = Command::new(env!("CARGO_BIN_EXE_rove-hop"))
        .arg("--socks5")
        .arg(format!("127.0.0.1:{socks5_port}"))
        .arg("--username")
        .arg("gate-service")
        .arg("--password")
        .arg(PROXY_PASSWORD)
        .arg("--mqtt-broker")
        .arg(format!("tcp://127.0.0.1:{broker_port}"))
        .arg("--mqtt-hop-id")
        .arg(HOP_ID)
        .arg("--mqtt-username")
        .arg("mqtt-user")
        .arg("--mqtt-password")
        .arg(MQTT_PASSWORD)
        .arg("--access-log-disable")
        .arg("--log-level")
        .arg("warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut hop = ChildGuard { child };
    match wait_for_tcp(socks5_port, &mut hop.child) {
        Ok(()) => Ok(hop),
        Err(error) => {
            let logs = std::fs::read_to_string(stderr_path).unwrap_or_default();
            Err(format!("{error}; stderr={logs}"))
        }
    }
}

fn wait_for_tcp(port: u16, child: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().ok().flatten() {
            return Err(format!("rove-hop exited before SOCKS5 listen: {status}"));
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("rove-hop SOCKS5 listener did not start".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn pick_free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .expect("ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

async fn start_broker() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mqtt");
    let port = listener.local_addr().expect("addr").port();
    let bus = Arc::new(Mutex::new(Broker::new()));
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let bus = bus.clone();
            tokio::spawn(async move {
                let _ = handle_mqtt_client(stream, bus).await;
            });
        }
    });
    port
}

async fn handle_mqtt_client(mut stream: TcpStream, bus: Arc<Mutex<Broker>>) -> std::io::Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Publish>();
    loop {
        tokio::select! {
            incoming = read_packet(&mut stream) => {
                let Some((first, payload)) = incoming? else {
                    return Ok(());
                };
                match first & 0xF0 {
                    0x10 => {
                        stream.write_all(&[0x20, 0x02, 0x00, 0x00]).await?;
                    }
                    0x80 | 0x82 => {
                        if payload.len() < 2 {
                            return Ok(());
                        }
                        let id = u16::from_be_bytes([payload[0], payload[1]]);
                        let mut rest = &payload[2..];
                        while rest.len() >= 2 {
                            let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                            if rest.len() < 2 + n + 1 {
                                break;
                            }
                            let topic = String::from_utf8_lossy(&rest[2..2 + n]).into_owned();
                            bus.lock().expect("broker").subs.entry(topic).or_default().push(tx.clone());
                            rest = &rest[2 + n + 1..];
                        }
                        let ack = [0x90, 0x03, (id >> 8) as u8, id as u8, 0x00];
                        stream.write_all(&ack).await?;
                    }
                    0x30 | 0x32 => {
                        if payload.len() < 2 {
                            return Ok(());
                        }
                        let tlen = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                        let qos = (first & 0x06) >> 1;
                        let mut offset = 2 + tlen;
                        let mut packet_id = 0u16;
                        if qos > 0 {
                            if payload.len() < offset + 2 {
                                return Ok(());
                            }
                            packet_id = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                            offset += 2;
                        }
                        if payload.len() < offset {
                            return Ok(());
                        }
                        let topic = String::from_utf8_lossy(&payload[2..2 + tlen]).into_owned();
                        let body = payload[offset..].to_vec();
                        if qos == 1 {
                            stream
                                .write_all(&[0x40, 0x02, (packet_id >> 8) as u8, packet_id as u8])
                                .await?;
                        }
                        let subscribers: Vec<_> = bus
                            .lock()
                            .expect("broker")
                            .subs
                            .iter()
                            .filter(|(filter, _)| topic_matches(filter, &topic))
                            .flat_map(|(_, txs)| txs.iter().cloned())
                            .collect();
                        for sub in subscribers {
                            let _ = sub.send(Publish {
                                topic: topic.clone(),
                                payload: body.clone(),
                            });
                        }
                    }
                    0xC0 => {
                        stream.write_all(&[0xD0, 0x00]).await?;
                    }
                    0xE0 => return Ok(()),
                    _ => {}
                }
            }
            outgoing = rx.recv() => {
                let Some(msg) = outgoing else { return Ok(()); };
                let topic = msg.topic.as_bytes();
                let mut pkt = Vec::new();
                pkt.extend_from_slice(&(topic.len() as u16).to_be_bytes());
                pkt.extend_from_slice(topic);
                pkt.extend_from_slice(&msg.payload);
                let mut out = vec![0x30];
                out.extend_from_slice(&encode_remaining_length(pkt.len()));
                out.extend_from_slice(&pkt);
                stream.write_all(&out).await?;
            }
        }
    }
}

async fn read_packet(stream: &mut TcpStream) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut first = [0u8; 1];
    match tokio::io::AsyncReadExt::read_exact(stream, &mut first).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut multiplier = 1usize;
    let mut len = 0usize;
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        len += (b[0] & 0x7F) as usize * multiplier;
        if b[0] & 0x80 == 0 {
            break;
        }
        multiplier *= 128;
        if multiplier > 128 * 128 * 128 {
            return Ok(None);
        }
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }
    Ok(Some((first[0], payload)))
}

fn topic_matches(filter: &str, topic: &str) -> bool {
    if filter == topic {
        return true;
    }
    if let Some(prefix) = filter.strip_suffix("/#") {
        return topic == prefix || topic.starts_with(&format!("{prefix}/"));
    }
    if filter.contains('+') {
        let f: Vec<&str> = filter.split('/').collect();
        let t: Vec<&str> = topic.split('/').collect();
        return f.len() == t.len() && f.iter().zip(t.iter()).all(|(a, b)| *a == "+" || *a == *b);
    }
    false
}

fn encode_remaining_length(mut len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if len == 0 {
            break;
        }
    }
    out
}
