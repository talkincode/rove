#![cfg(unix)]

mod common;

use base64::Engine as _;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;

const START_TIMEOUT: Duration = Duration::from_secs(15);
const SECONDARY_CERT: &str = include_str!("fixtures/tls/secondary.crt");
const SECONDARY_KEY: &str = include_str!("fixtures/tls/secondary.key");

enum SniLayout {
    Single,
    Duplicate,
    CertificateMismatch,
    EmptyServerNames,
}

struct NodeUnderTest {
    child: Child,
    workdir: PathBuf,
    stderr_path: PathBuf,
    proxy_port: u16,
}

impl Drop for NodeUnderTest {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

impl NodeUnderTest {
    async fn connect_tls(&mut self, server_name: &str) -> TlsStream<TcpStream> {
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll rove process") {
                let stderr = std::fs::read_to_string(&self.stderr_path).unwrap_or_default();
                panic!("rove exited before TLS became ready ({status:?}): {stderr}");
            }

            if let Ok(tcp) = TcpStream::connect(("127.0.0.1", self.proxy_port)).await {
                let connector = rove::tls::insecure_client_connector();
                let name = ServerName::try_from(server_name.to_string())
                    .expect("valid test SNI")
                    .to_owned();
                if let Ok(tls) = connector.connect(name, tcp).await {
                    return tls;
                }
            }

            assert!(
                Instant::now() < deadline,
                "rove TLS listener did not become ready within {START_TIMEOUT:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[tokio::test]
async fn single_tls_listener_selects_certificates_by_sni_and_tunnels_http_connect() {
    rove::tls::init_crypto();
    let mut node = spawn_node(SniLayout::Single);
    let (target, echo_task) = start_echo_server(2).await;

    let mut default_tls = node.connect_tls("localhost").await;
    assert_served_certificate(&default_tls, common::TEST_CERT);
    assert_http_connect_tunnel(&mut default_tls, target, b"default").await;

    let mut secondary_tls = node.connect_tls("secondary.test").await;
    assert_served_certificate(&secondary_tls, SECONDARY_CERT);
    assert_http_connect_tunnel(&mut secondary_tls, target, b"secondary").await;

    echo_task.await.expect("echo server task");
}

#[test]
fn duplicate_sni_mapping_fails_startup() {
    assert_startup_failure(
        spawn_node(SniLayout::Duplicate),
        "duplicate SNI server name",
    );
}

#[test]
fn certificate_that_does_not_cover_sni_fails_startup() {
    assert_startup_failure(
        spawn_node(SniLayout::CertificateMismatch),
        "map SNI \"wrong.test\"",
    );
}

#[test]
fn certificate_without_server_names_fails_startup() {
    assert_startup_failure(
        spawn_node(SniLayout::EmptyServerNames),
        "requires at least one server name",
    );
}

fn assert_startup_failure(mut node: NodeUnderTest, expected_error: &str) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = node.child.try_wait().expect("poll rove process") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "rove accepted an invalid SNI mapping instead of failing startup"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let stderr = std::fs::read_to_string(&node.stderr_path).unwrap_or_default();
    assert!(!status.success(), "invalid SNI mapping must fail startup");
    assert!(
        stderr.contains(expected_error),
        "startup error must identify the invalid SNI mapping: {stderr}"
    );
}

fn spawn_node(layout: SniLayout) -> NodeUnderTest {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let proxy_port = pick_free_port();
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let workdir = std::env::temp_dir().join(format!("rove-tls-sni-it-{pid}-{seq}"));
    std::fs::create_dir_all(&workdir).expect("create workdir");

    let default_cert = workdir.join("default.crt");
    let default_key = workdir.join("default.key");
    let secondary_cert = workdir.join("secondary.crt");
    let secondary_key = workdir.join("secondary.key");
    let cache_path = workdir.join("snapshot.json");
    std::fs::write(&default_cert, common::TEST_CERT).expect("write default cert");
    std::fs::write(&default_key, common::TEST_KEY).expect("write default key");
    std::fs::write(&secondary_cert, SECONDARY_CERT).expect("write secondary cert");
    std::fs::write(&secondary_key, SECONDARY_KEY).expect("write secondary key");
    std::fs::write(
        &cache_path,
        r#"{
  "version": 1,
  "users": {
    "alice": {
      "password": "secret",
      "group": "default"
    }
  },
  "groups": {
    "default": {
      "proxy": [],
      "block": []
    }
  }
}"#,
    )
    .expect("write snapshot cache");

    let additional_certificates = match layout {
        SniLayout::Single => format!(
            r#"[[listeners.tls.certificates]]
server_names = ["secondary.test"]
cert = "{secondary_cert}"
key = "{secondary_key}"
"#,
            secondary_cert = secondary_cert.display(),
            secondary_key = secondary_key.display(),
        ),
        SniLayout::Duplicate => format!(
            r#"[[listeners.tls.certificates]]
server_names = ["secondary.test"]
cert = "{secondary_cert}"
key = "{secondary_key}"

[[listeners.tls.certificates]]
server_names = ["Secondary.Test"]
cert = "{secondary_cert}"
key = "{secondary_key}"
"#,
            secondary_cert = secondary_cert.display(),
            secondary_key = secondary_key.display(),
        ),
        SniLayout::CertificateMismatch => format!(
            r#"[[listeners.tls.certificates]]
server_names = ["wrong.test"]
cert = "{secondary_cert}"
key = "{secondary_key}"
"#,
            secondary_cert = secondary_cert.display(),
            secondary_key = secondary_key.display(),
        ),
        SniLayout::EmptyServerNames => format!(
            r#"[[listeners.tls.certificates]]
server_names = []
cert = "{secondary_cert}"
key = "{secondary_key}"
"#,
            secondary_cert = secondary_cert.display(),
            secondary_key = secondary_key.display(),
        ),
    };
    let config_path = workdir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"node_id = "tls-sni-it"

[control_plane]
snapshot_url = "http://127.0.0.1:1/snapshot"
token = "test"
cache_path = "{cache}"

[[listeners]]
name = "https-in"
protocol = "http"
listen = "127.0.0.1:{proxy_port}"

[listeners.tls]
cert = "{default_cert}"
key = "{default_key}"

{additional_certificates}

[access_log]
enable = false
"#,
            cache = cache_path.display(),
            default_cert = default_cert.display(),
            default_key = default_key.display(),
        ),
    )
    .expect("write config");

    let stderr_path = workdir.join("stderr.log");
    let stderr = std::fs::File::create(&stderr_path).expect("create stderr log");
    let child = Command::new(env!("CARGO_BIN_EXE_rove"))
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn rove");

    NodeUnderTest {
        child,
        workdir,
        stderr_path,
        proxy_port,
    }
}

fn pick_free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn assert_served_certificate(tls: &TlsStream<TcpStream>, expected_pem: &str) {
    let served = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .expect("server leaf certificate");
    let expected = parse_leaf_certificate(expected_pem);
    assert_eq!(
        served.as_ref(),
        expected.as_ref(),
        "listener served the wrong certificate for the requested SNI"
    );
}

fn parse_leaf_certificate(pem: &str) -> CertificateDer<'static> {
    let certificate = CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .expect("certificate PEM entry")
        .expect("parse certificate PEM");
    certificate
}

async fn assert_http_connect_tunnel(
    tls: &mut TlsStream<TcpStream>,
    target: SocketAddr,
    payload: &[u8],
) {
    let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
    tls.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("write CONNECT");
    let response = rove::util::read_http_head(tls, 8192)
        .await
        .expect("read CONNECT response");
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {}",
        String::from_utf8_lossy(&response)
    );

    tls.write_all(payload).await.expect("write tunnel payload");
    let mut echoed = vec![0; payload.len()];
    tls.read_exact(&mut echoed)
        .await
        .expect("read tunnel payload");
    assert_eq!(echoed, payload);
    tls.shutdown().await.expect("close tunnel");
}

async fn start_echo_server(expected_connections: usize) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("echo address");
    let task = tokio::spawn(async move {
        for _ in 0..expected_connections {
            let (mut stream, _) = listener.accept().await.expect("accept echo connection");
            let mut buffer = [0u8; 1024];
            loop {
                let read = stream.read(&mut buffer).await.expect("read echo bytes");
                if read == 0 {
                    break;
                }
                stream
                    .write_all(&buffer[..read])
                    .await
                    .expect("write echo bytes");
            }
        }
    });
    (addr, task)
}
