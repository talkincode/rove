//! Graceful-shutdown integration: a production node must exit cleanly on
//! SIGTERM (what `docker stop`, Kubernetes and systemd send) exactly as it
//! does on SIGINT (ctrl_c). "Cleanly" means: the process observes the signal
//! and returns from main with exit code 0 within a bounded time, instead of
//! being killed by the default signal disposition (exit by signal 15).
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const READY_TIMEOUT: Duration = Duration::from_secs(15);
const EXIT_TIMEOUT: Duration = Duration::from_secs(5);

// Each test hands an OS-selected free port to a child process. Keep that
// bind/release/spawn window serial so parallel tests cannot select the same
// port and mistake another test's listener for their own.
static SHUTDOWN_TEST_LOCK: Mutex<()> = Mutex::new(());

struct NodeUnderTest {
    child: Child,
    _workdir: PathBuf,
    proxy_port: u16,
    _serial: MutexGuard<'static, ()>,
}

fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn spawn_node(test_name: &str) -> NodeUnderTest {
    spawn_node_with(test_name, false, 30)
}

fn spawn_node_with(test_name: &str, write_snapshot: bool, grace_period_secs: u64) -> NodeUnderTest {
    let serial = SHUTDOWN_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let port = pick_free_port();
    let workdir = std::env::temp_dir().join(format!(
        "rove-shutdown-{test_name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&workdir).expect("create test workdir");
    let cache_path = workdir.join("snapshot.json");
    if write_snapshot {
        std::fs::write(
            &cache_path,
            r#"{
  "schema_version": 1,
  "version": 1,
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
        .expect("write snapshot cache");
    }

    // Minimal viable config: unreachable control plane (sync retries in the
    // background and must not block startup or shutdown), one HTTP listener,
    // access log disabled so nothing is written outside the temp workdir.
    let config = format!(
        r#"node_id = "shutdown-test"

[control_plane]
snapshot_url = "http://127.0.0.1:1/snapshot"
token = "test"
cache_path = "{cache}"

[shutdown]
grace_period_secs = {grace_period_secs}

[[listeners]]
name = "http-in"
protocol = "http"
listen = "127.0.0.1:{port}"

[log]
level = "info"

[access_log]
enable = false
"#,
        cache = cache_path.display(),
    );
    let config_path = workdir.join("config.toml");
    let mut f = std::fs::File::create(&config_path).expect("write config");
    f.write_all(config.as_bytes()).expect("write config body");

    let child = Command::new(env!("CARGO_BIN_EXE_rove"))
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rove binary");

    // Readiness = the listener accepts TCP connections.
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "rove did not open its listener within {READY_TIMEOUT:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    NodeUnderTest {
        child,
        _workdir: workdir,
        proxy_port: port,
        _serial: serial,
    }
}

fn send_signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{signal} {pid} failed");
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + EXIT_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            panic!("rove did not exit within {EXIT_TIMEOUT:?} after the signal");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn assert_clean_exit_on(signal: &str, test_name: &str) {
    let mut node = spawn_node(test_name);
    send_signal(node.child.id(), signal);
    let status = wait_for_exit(&mut node.child);
    assert!(
        status.success(),
        "expected clean exit (code 0) after SIG{signal}, got {status:?}"
    );
}

#[test]
fn node_exits_cleanly_on_sigterm() {
    assert_clean_exit_on("TERM", "sigterm");
}

#[test]
fn node_exits_cleanly_on_sigint() {
    assert_clean_exit_on("INT", "sigint");
}

#[test]
fn sigterm_stops_accepting_and_allows_inflight_tunnel_to_finish() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_addr = target.local_addr().expect("target addr");
    let target_task = std::thread::spawn(move || {
        let (mut stream, _) = target.accept().expect("accept target connection");
        let mut buf = [0u8; 5];
        while stream.read_exact(&mut buf).is_ok() {
            stream.write_all(&buf).expect("echo target bytes");
        }
    });

    let mut node = spawn_node_with("drain-inflight", true, 3);
    let mut client =
        TcpStream::connect(("127.0.0.1", node.proxy_port)).expect("connect proxy listener");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    client
        .set_write_timeout(Some(Duration::from_secs(3)))
        .expect("set write timeout");
    client
        .write_all(
            format!(
                "CONNECT {target_addr} HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write CONNECT");
    let response = read_http_head(&mut client);
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {response}"
    );

    client.write_all(b"first").expect("write before signal");
    let mut echoed = [0u8; 5];
    client.read_exact(&mut echoed).expect("read before signal");
    assert_eq!(&echoed, b"first");

    send_signal(node.child.id(), "TERM");
    wait_until_listener_closes(node.proxy_port);

    client.write_all(b"after").expect("write during drain");
    client.read_exact(&mut echoed).expect("read during drain");
    assert_eq!(&echoed, b"after");
    drop(client);

    let status = wait_for_exit(&mut node.child);
    assert!(status.success(), "drained process exited with {status:?}");
    target_task.join().expect("target task");
}

#[test]
fn graceful_shutdown_forces_exit_after_drain_timeout() {
    let target = TcpListener::bind("127.0.0.1:0").expect("bind target");
    let target_addr = target.local_addr().expect("target addr");
    let target_task = std::thread::spawn(move || {
        let (mut stream, _) = target.accept().expect("accept target connection");
        let mut byte = [0u8; 1];
        let _ = stream.read(&mut byte);
    });

    let mut node = spawn_node_with("drain-timeout", true, 1);
    let mut client =
        TcpStream::connect(("127.0.0.1", node.proxy_port)).expect("connect proxy listener");
    client
        .write_all(
            format!(
                "CONNECT {target_addr} HTTP/1.1\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n"
            )
            .as_bytes(),
        )
        .expect("write CONNECT");
    let response = read_http_head(&mut client);
    assert!(response.starts_with("HTTP/1.1 200"));

    let started = Instant::now();
    send_signal(node.child.id(), "TERM");
    let status = wait_for_exit(&mut node.child);
    let elapsed = started.elapsed();
    assert!(status.success(), "timed-out drain exited with {status:?}");
    assert!(
        elapsed >= Duration::from_millis(800),
        "process exited before the configured drain window: {elapsed:?}"
    );
    assert!(
        elapsed < EXIT_TIMEOUT,
        "process exceeded the bounded drain timeout: {elapsed:?}"
    );

    drop(client);
    target_task.join().expect("target task");
}

fn read_http_head(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).expect("read HTTP response");
        response.push(byte[0]);
        assert!(response.len() <= 8192, "HTTP response header too large");
    }
    String::from_utf8(response).expect("HTTP response is UTF-8")
}

fn wait_until_listener_closes(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => drop(stream),
            Err(_) => return,
        }
        assert!(
            Instant::now() < deadline,
            "listener still accepted new connections after SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
