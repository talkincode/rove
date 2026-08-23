#![cfg(unix)]

//! Process-level snapshot sync E2E: a real `rove` binary against a real HTTP
//! control-plane listener. Complements the in-process `src/sync` tests.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(15);
const TOKEN: &str = "snapshot-e2e-token";
const USER: &str = "alice";
const PASS: &str = "secret";

const OPEN_SNAPSHOT: &str = r#"{
  "version": 1,
  "users": { "alice": { "password": "secret", "group": "default" } },
  "groups": { "default": { "proxy": [], "block": [] } }
}"#;

const BLOCK_SNAPSHOT: &str = r#"{
  "version": 2,
  "users": { "alice": { "password": "secret", "group": "default" } },
  "groups": { "default": { "proxy": [], "block": ["blocked.example"] } }
}"#;

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

struct SnapshotHttp {
    body: Arc<Mutex<Vec<u8>>>,
    status: Arc<Mutex<u16>>,
}

impl SnapshotHttp {
    fn spawn(initial_body: &str, initial_status: u16) -> (u16, Self) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind snapshot http");
        let port = listener.local_addr().expect("snapshot addr").port();
        let body = Arc::new(Mutex::new(initial_body.as_bytes().to_vec()));
        let status = Arc::new(Mutex::new(initial_status));
        let serve_body = body.clone();
        let serve_status = status.clone();
        thread::spawn(move || {
            listener.set_nonblocking(false).ok();
            while let Ok((mut stream, _)) = listener.accept() {
                let request = read_http_head(&mut stream);
                let authorized = request.to_ascii_lowercase().contains(&format!(
                    "authorization: bearer {}",
                    TOKEN.to_ascii_lowercase()
                ));
                let (code, payload) = if !authorized {
                    (401u16, Vec::new())
                } else {
                    let code = *serve_status.lock().expect("status");
                    let payload = serve_body.lock().expect("body").clone();
                    (code, payload)
                };
                let reason = match code {
                    200 => "OK",
                    304 => "Not Modified",
                    401 => "Unauthorized",
                    _ => "Error",
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(&payload);
            }
        });
        (port, SnapshotHttp { body, status })
    }

    fn set_body(&self, body: &str) {
        *self.body.lock().expect("body") = body.as_bytes().to_vec();
        *self.status.lock().expect("status") = 200;
    }

    fn set_status(&self, status: u16) {
        *self.status.lock().expect("status") = status;
    }
}

#[test]
fn rove_process_applies_remote_snapshot_and_blocks_new_selector() {
    let (cp_port, control) = SnapshotHttp::spawn(OPEN_SNAPSHOT, 200);
    let env = start_node(cp_port, OPEN_SNAPSHOT);
    assert_eq!(
        connect_status(env.proxy_port, "blocked.example:443"),
        502,
        "version 1 must still attempt the later-blocked host (dial fail, not policy)"
    );

    control.set_body(BLOCK_SNAPSHOT);
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if connect_status(env.proxy_port, "blocked.example:443") == 403 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "rove never applied the blocking snapshot"
        );
        thread::sleep(Duration::from_millis(150));
    }
    assert_eq!(
        connect_status(env.proxy_port, "allowed.example:443"),
        502,
        "unblocked host still leaves the node (dial fail), not 403"
    );
}

#[test]
fn rove_process_rejects_invalid_remote_snapshot_without_replacing_cache() {
    let (cp_port, control) = SnapshotHttp::spawn(OPEN_SNAPSHOT, 200);
    let env = start_node(cp_port, OPEN_SNAPSHOT);
    let cache_before = std::fs::read(&env.cache_path).expect("read cache");

    control.set_body("this is not a snapshot");
    thread::sleep(Duration::from_secs(3));

    let cache_after = std::fs::read(&env.cache_path).expect("read cache after bad sync");
    assert_eq!(
        cache_before, cache_after,
        "invalid remote snapshot must not overwrite the cache"
    );
    assert_eq!(
        connect_status(env.proxy_port, "still-open.example:443"),
        502,
        "cached open policy must keep serving after a bad remote snapshot"
    );
}

#[test]
fn rove_process_rejected_token_fails_closed_without_touching_cache() {
    let (cp_port, control) = SnapshotHttp::spawn(OPEN_SNAPSHOT, 200);
    let env = start_node(cp_port, OPEN_SNAPSHOT);
    let cache_before = std::fs::read(&env.cache_path).expect("read cache");

    control.set_status(401);
    thread::sleep(Duration::from_secs(3));

    let cache_after = std::fs::read(&env.cache_path).expect("read cache after 401");
    assert_eq!(cache_before, cache_after);
    assert_eq!(
        connect_status(env.proxy_port, "still-open.example:443"),
        502,
        "401 from the control plane must keep the last good snapshot in service"
    );
}

struct NodeEnv {
    _node: ChildGuard,
    proxy_port: u16,
    cache_path: PathBuf,
}

fn start_node(snapshot_port: u16, cache_body: &str) -> NodeEnv {
    let mut last = String::new();
    for attempt in 0..8 {
        match try_start_node(snapshot_port, cache_body, attempt) {
            Ok(env) => return env,
            Err(error) => last = error,
        }
    }
    panic!("rove failed to start after retries: {last}");
}

fn try_start_node(snapshot_port: u16, cache_body: &str, attempt: u32) -> Result<NodeEnv, String> {
    let workdir = std::env::temp_dir().join(format!(
        "rove-sync-it-{}-{}-{}",
        std::process::id(),
        nanos(),
        attempt
    ));
    std::fs::create_dir_all(&workdir).map_err(|e| e.to_string())?;
    let cache_path = workdir.join("snapshot.json");
    std::fs::write(&cache_path, cache_body).map_err(|e| e.to_string())?;
    let proxy_port = pick_free_port();
    let health_port = pick_free_port();
    let config_path = workdir.join("config.toml");
    let stderr_path = workdir.join("rove.err");
    std::fs::write(
        &config_path,
        format!(
            r#"node_id = "sync-e2e"

[control_plane]
snapshot_url = "http://127.0.0.1:{snapshot_port}/snapshot"
token = "{TOKEN}"
poll_interval_secs = 1
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

[access_log]
enable = false
"#,
            cache = cache_path.display()
        ),
    )
    .map_err(|e| e.to_string())?;

    let stderr = std::fs::File::create(&stderr_path).map_err(|e| e.to_string())?;
    let child = Command::new(env!("CARGO_BIN_EXE_rove"))
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut node = ChildGuard {
        child,
        _workdir: workdir,
    };
    match wait_for_health(health_port, &mut node.child) {
        Ok(()) => Ok(NodeEnv {
            _node: node,
            proxy_port,
            cache_path,
        }),
        Err(error) => {
            let logs = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            Err(format!("{error}; stderr={logs}"))
        }
    }
}

fn connect_status(proxy_port: u16, target: &str) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).expect("connect proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    let token = base64_basic(USER, PASS);
    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).expect("write CONNECT");
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..n]);
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn wait_for_health(port: u16, child: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().ok().flatten() {
            return Err(format!("rove exited before health: {status}"));
        }
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            let mut buf = [0u8; 128];
            if stream.read(&mut buf).unwrap_or(0) > 0 {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("rove health endpoint did not start".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_http_head(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 16 * 1024 {
        if stream.read(&mut byte).unwrap_or(0) == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos()
}

fn base64_basic(user: &str, pass: &str) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{user}:{pass}"),
    )
}
