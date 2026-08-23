#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const START_TIMEOUT: Duration = Duration::from_secs(15);

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

#[test]
fn health_endpoints_report_snapshot_and_sustained_control_plane_failure() {
    let proxy_port = pick_free_port();
    let health_port = pick_free_port();
    let workdir = std::env::temp_dir().join(format!(
        "rove-health-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&workdir).expect("create workdir");
    let cache_path = workdir.join("snapshot.json");
    std::fs::write(
        &cache_path,
        r#"{
  "schema_version": 1,
  "version": 42,
  "users": {
    "alice": {
      "password": "secret",
      "policy": "default"
    }
  },
  "routing_policies": {
    "default": {
      "routes": []
    }
  }
}"#,
    )
    .expect("write snapshot");
    let config_path = workdir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"node_id = "health-it"

[control_plane]
snapshot_url = "http://127.0.0.1:1/snapshot"
token = "secret-node-token"
cache_path = "{cache}"

[health]
enable = true
listen = "127.0.0.1:{health_port}"
control_plane_unreachable_secs = 2

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
    .expect("write config");

    let child = Command::new(env!("CARGO_BIN_EXE_rove"))
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rove");
    let mut node = ChildGuard {
        child,
        _workdir: workdir,
    };

    let health = wait_for_response(health_port, "/healthz", START_TIMEOUT);
    assert_eq!(health.0, 200);
    assert!(health.1.contains("\"version\":42"));
    assert!(!health.1.contains("secret-node-token"));
    assert!(!health.1.contains("snapshot_url"));

    let ready = request(health_port, "/readyz").expect("ready response");
    assert_eq!(ready.0, 200);
    assert!(ready.1.contains("\"status\":\"ready\""));
    assert!(ready.1.contains("\"required\":true"));
    assert!(ready.1.contains("\"active_listeners\":1"));

    let deadline = Instant::now() + Duration::from_secs(5);
    let degraded = loop {
        let response = request(health_port, "/readyz").expect("ready response");
        if response.0 == 503 {
            break response;
        }
        assert!(
            Instant::now() < deadline,
            "readiness never reported sustained control-plane failure"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(degraded.1.contains("\"status\":\"degraded\""));
    assert!(degraded.1.contains("\"status\":\"unreachable\""));

    let liveness = request(health_port, "/healthz").expect("liveness response");
    assert_eq!(liveness.0, 200);

    send_term(node.child.id());
    let status = wait_for_exit(&mut node.child, Duration::from_secs(5));
    assert!(status.success(), "rove exited with {status:?}");
}

#[test]
fn configured_listener_bind_failure_exits_nonzero() {
    let occupied = TcpListener::bind("127.0.0.1:0").expect("occupy listener port");
    let proxy_port = occupied.local_addr().expect("occupied address").port();
    let workdir = std::env::temp_dir().join(format!(
        "rove-listener-failure-it-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&workdir).expect("create workdir");
    let config_path = workdir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"node_id = "listener-failure-it"

[control_plane]
snapshot_url = "http://127.0.0.1:1/snapshot"
token = "test-token"
cache_path = "{cache}"

[[listeners]]
name = "http-in"
protocol = "http"
listen = "127.0.0.1:{proxy_port}"

[access_log]
enable = false
"#,
            cache = workdir.join("snapshot.json").display()
        ),
    )
    .expect("write config");

    let child = Command::new(env!("CARGO_BIN_EXE_rove"))
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rove");
    let mut node = ChildGuard {
        child,
        _workdir: workdir,
    };

    let status = wait_for_exit(&mut node.child, START_TIMEOUT);
    assert!(
        !status.success(),
        "listener bind failure must fail startup, got {status:?}"
    );
}

fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn wait_for_response(port: u16, path: &str, timeout: Duration) -> (u16, String) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(response) = request(port, path) {
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "health endpoint did not start within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn request(port: u16, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .ok()?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).ok()?;
    let response = String::from_utf8(bytes).ok()?;
    let status = response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Some((status, body))
}

fn send_term(pid: u32) {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("send SIGTERM");
    assert!(status.success());
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "rove did not exit within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
