//! MQTT E2E over a real TCP broker: `rumqttc` on both sides, plus a real `rove`
//! process. Complements the in-process contract tests in `src/mqtt.rs`.

#![cfg(unix)]

use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener as StdListener, TcpStream as StdStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const TOKEN: &str = "mqtt-e2e-token";
const PASSWORD: &str = "secret";

struct ChildGuard {
    child: Child,
    _workdir: PathBuf,
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
    /// Subscription filters (may include `#` / `+`) → live client queues.
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
async fn rove_process_answers_user_policy_query_over_real_broker_without_leaking_password() {
    let broker_port = start_broker().await;
    let (_node, health_port) = start_rove(broker_port);
    wait_for_health(health_port);

    let mut options = MqttOptions::new("e2e-controller", "127.0.0.1", broker_port);
    options.set_keep_alive(Duration::from_secs(5));
    options.set_clean_session(true);
    let (client, mut eventloop) = AsyncClient::new(options, 16);
    client
        .subscribe("rove/replies/#", QoS::AtLeastOnce)
        .await
        .unwrap();
    client
        .subscribe("rove/node/status", QoS::AtLeastOnce)
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

    // Give rove time to connect and subscribe before we publish the query.
    tokio::time::sleep(Duration::from_secs(2)).await;
    client
        .publish(
            "rove/user/query",
            QoS::AtLeastOnce,
            false,
            br#"{
                "command":"user_policy_query",
                "request_id":"query-e2e",
                "reply_topic":"rove/replies/query-e2e",
                "data":{"username":"alice"}
            }"#,
        )
        .await
        .unwrap();

    let replies = pump.await.expect("controller eventloop");
    assert_eq!(replies.len(), 1, "expected one policy query reply");
    let body = String::from_utf8(replies[0].clone()).expect("utf8 reply");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json reply");
    assert_eq!(parsed["status"], "ok");
    assert_eq!(parsed["user"]["username"], "alice");
    assert!(
        parsed["user"].get("password").is_none(),
        "policy query must not leak the password: {body}"
    );
    assert!(
        !body.contains(PASSWORD),
        "raw reply must not contain the user password: {body}"
    );
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
                        stream
                            .write_all(&[0x20, 0x02, 0x00, 0x00])
                            .await?;
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

fn start_rove(broker_port: u16) -> (ChildGuard, u16) {
    let workdir = std::env::temp_dir().join(format!(
        "rove-mqtt-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&workdir).expect("workdir");
    let cache_path = workdir.join("snapshot.json");
    std::fs::write(
        &cache_path,
        r#"{
  "schema_version": 1,
  "version": 7,
  "users": { "alice": { "password": "secret", "policy": "default" } },
  "routing_policies": { "default": { "routes": [] } }
}"#,
    )
    .expect("cache");
    let proxy_port = pick_free_port();
    let health_port = pick_free_port();
    let config_path = workdir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"node_id = "mqtt-e2e"

[control_plane]
snapshot_url = "http://127.0.0.1:1/snapshot"
token = "{TOKEN}"
cache_path = "{cache}"

[health]
enable = true
listen = "127.0.0.1:{health_port}"

[shutdown]
grace_period_secs = 1

[[listeners]]
name = "http-in"
protocol = "http"
listen = "127.0.0.1:{proxy_port}"

[mqtt]
enable = true
broker = "tcp://127.0.0.1:{broker_port}"
client_id = "rove-mqtt-e2e"
qos = 1

[access_log]
enable = false
"#,
            cache = cache_path.display()
        ),
    )
    .expect("config");

    let stderr = std::fs::File::create(workdir.join("rove.err")).expect("stderr file");
    let child = Command::new(env!("CARGO_BIN_EXE_rove"))
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn rove");
    (
        ChildGuard {
            child,
            _workdir: workdir,
        },
        health_port,
    )
}

fn wait_for_health(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(mut stream) = StdStream::connect(("127.0.0.1", port)) {
            let _ = stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            let mut buf = [0u8; 64];
            if stream.read(&mut buf).unwrap_or(0) > 0 {
                return;
            }
        }
        assert!(Instant::now() < deadline, "rove did not become healthy");
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
