//! End-to-end coverage for the independently deployed `rove-hop` forward proxy.
//! The tests exercise the built binary rather than calling its listener module.

use base64::Engine as _;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::{client::TlsStream, TlsConnector};

const START_TIMEOUT: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(3);
const USERNAME: &str = "gate-service";
const PASSWORD: &str = "egress-secret";
const TEST_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUCXh7fObeTJs13J37uwroS/THcjIwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPcnRwLWhvcC10ZXN0LWNhMB4XDTI2MDcxMjE3MDEwOFoX
DTM2MDcwOTE3MDEwOFowGjEYMBYGA1UEAwwPcnRwLWhvcC10ZXN0LWNhMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxLvUgKF0emkEEjJpad+JbjgknOTJ
FG7gY3nQ14XxpefkhZVnhG725H/XMzqkwDmqCA2eHG+dhsFaYHvfROvkDlYc+kB3
fODvPpT1OFN9kiJUcRJLeo9q+5rc3P3xzjikKznlkaFLi+JeNsG6cJc//nSzLE3/
SERQ1iqoibQ4UcD4O2FlXTfWvY8xFHQN26Qfox7wqzG5ZCXPTex8D7qxHzk5JOvt
hXbc8wRYBgprWI8pt/xad9fe7nK0vYdzHW5HZ+668rykRLEU9q7sQJyiaF+432Th
EnyzPP6pUYjSnX5A8AVWuhneol1lOlozefmIg7t0Zf7/8wQw908T3OHrZQIDAQAB
o2MwYTAdBgNVHQ4EFgQUsB9Gbq7BMgv0n5+9TvV/nD5dhOwwHwYDVR0jBBgwFoAU
sB9Gbq7BMgv0n5+9TvV/nD5dhOwwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAQYwDQYJKoZIhvcNAQELBQADggEBAL6fFt8H/wYhKkPSFVHn79wyT4lkl0Dn
e4GCjzx2vEOOPNbPk8GMFaLX41m2Sm0rjaGxfatclFEYmZ07JIQAMKlKT4ZYlxIB
M9xaeIjGPgk4w/38Vhr/za962PtDRgmYL50qv1uAPJJo6Y55aVLO5XpNb2Hw/8xR
w4eujExEIFAjGT9DPDEI+yLDdy3i7Sq+cTUhYj1PH+6v1Nz5FHDH+snPgu9Abl+M
hhbQw3uojJ9D/aQznPzD/ExG4lhBd0Fqy1x7pNubA6fKJ7nfUKHYP67CIU9kKKcj
nCXHkKig2DmpLS7TZhnXoYSc5PIJTiAclpHZOBK6QvZ4g+6FGhcjROE=
-----END CERTIFICATE-----"#;
const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIULMHzMaZFOaSoAKZhZiO/fMQeTDEwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPcnRwLWhvcC10ZXN0LWNhMB4XDTI2MDcxMjE3MDEwOFoX
DTM2MDcwOTE3MDEwOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr9WUWh35YgqBqT6X3PYePwYBiTVM818jzbFs
uSlHpHVTCV1UZVTm/HcFsoi9meYNWF/ROZmwZod+vsuXS3T9obnVwcc/am0HtZAs
JHGbOD/B/N6DyUxdFXyUj7JoKoi/6vXBqYsPohtH9QBS+kO89bK94ypPUcHijEtb
DN0uj5VqGrQHsLmeV85bJtuFW4A/2DtIrhq0Lc5nEhVU2cErUierEwgiomrQ9Bd4
NHTolpOp210+HhM5uDb656/dkcW2jh+UxcmxAmWN+QD4yxSw/5T5Tw1x8RP9CP6i
p5XXCMlWSmkXxjYizF4CBf03LPw4oHr+c8WkAkKWpl7JHwvGwQIDAQABo4GMMIGJ
MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAdBgNVHQ4EFgQUlECce90m7k1r1+Sy
0nO0ktCEZu4wHwYDVR0jBBgwFoAUsB9Gbq7BMgv0n5+9TvV/nD5dhOwwDQYJKoZI
hvcNAQELBQADggEBAGr8hOf2lQR6Hdcmnqx6XjsRBe0ZCs3OI01BgPumovCSOYVo
oxqBE8xyykSwHMTln+RmwnlfF/GrBjFLfyF2SUrlSJAGez6JTsK6gTMCf8XI7q/O
lvPa7fBYrCBHSThJpM4hyTs158M/PN6ySsRUau45Alwt28n1xo2c8IqQ0YawgnsA
oboD6Qu+2Sh/4Kn9VcA1bqaONJi/0tkgAHet6N2Fo0lQbHk8I2e+al3Vp9S5yMtY
WkTsvouyg+t4C5uhf2MkMaVqJE9/fLb4hgzG+FizbXugs/4OuNMpGO/b9E+hwyH7
imij5vlW8US6KMvPNY8PKmHKmqTo9FVtRehayZ0=
-----END CERTIFICATE-----"#;
const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCv1ZRaHfliCoGp
Ppfc9h4/BgGJNUzzXyPNsWy5KUekdVMJXVRlVOb8dwWyiL2Z5g1YX9E5mbBmh36+
y5dLdP2hudXBxz9qbQe1kCwkcZs4P8H83oPJTF0VfJSPsmgqiL/q9cGpiw+iG0f1
AFL6Q7z1sr3jKk9RweKMS1sM3S6PlWoatAewuZ5Xzlsm24VbgD/YO0iuGrQtzmcS
FVTZwStSJ6sTCCKiatD0F3g0dOiWk6nbXT4eEzm4Nvrnr92RxbaOH5TFybECZY35
APjLFLD/lPlPDXHxE/0I/qKnldcIyVZKaRfGNiLMXgIF/Tcs/Digev5zxaQCQpam
XskfC8bBAgMBAAECggEAB1eLNMIYpivbIyZ+b9cFB0uoZ8LGfkkENTQJ3qdnGupd
N8BiZELJzFPp9Hz6McFl4EFL+rQ8peNVewEERb3SU1zvnIJF1xtLXZzyAumNeilL
X9Qou5CJOHr1txRTficsoFJ3ri0kz3eFJylGzbVjX/0BKcmb+0V1wLbqy9w2c/9O
3lYgwXPDm5jwbAHO5/Y77giivx2bvXXxalJmh905Kkb91t07h1wIgqUrxPCMxbMF
1eMmniadhA5XEyPtYWD6E3KgGQg0cXWOWnuDosGe0udARL2qViaCLTeuv0XRn5Md
uy1nSQBzHD8zM0/C8I9k9qss2M79x8cxzZFn3W4AmQKBgQDonR/fnh1wAJJOrhe8
FO44NDI5CP7TpeNv8akKcRwstGzHPI3yWJ1G1x9Q6zem1bd8uusq+lg6ieABRtbX
1S2t8MupUb1pkUzdmwRfV5Bpm7+i46Eg98ahTXWI5Yp0n9tKe2KB604zN1oeIa+T
uv77Q0cmM3h/AntAMb6gqZ8+pQKBgQDBgxk5F2EZNh0I9/iybJXgIzXwYC0OmREx
Mk7uANOsYq9rT9oWab6VaoFmSCIzdrGni6fFpt2wNWqPxzP/fKprpPrnCq6jPvQg
24scrUKNaPi68KUMF2SfKTx8gR1PGgtwZPlZ/esnIetijsFWJIuS9OGQ37nXa7zm
N7R29nEo7QKBgQCzrquwULLskYRywogTARgC0k75P7mYQ8wr7MBnEHhzD+v2+w+q
5EiZMBNArnGOrgfOkZSW3krI7TfbxJywnDts4VRwtnNZ2KNHizcVbs5exbCCYtNU
ZBFLCEqCNM1+yPzby/OL5/fAGEHEhMDbnNbZwF51Y8zwTzplnAdkk6IvAQKBgAFo
j91vgyBo2WtASsoZqjmYaAMY4BsUGCDwicyHqwK9MSOp0B+Lo3x46vowmjcfrQlY
Jd91aHWo3d6wB3vbj237JGxcEotToPlAP9H0nOBknDLYH4tn/C6AYVVSp0D1IpIt
2fbCt1xwjcMI4PVcjLuEFsQ0LKkZuqU+UIzxHD+9AoGBAMXJbXR21jmteDrOxB2+
iATmob/BkkC+BhhxMET/Ii+meqpnKyutJUfaho64dsA2clTllgQaVc/FBXgouPIN
zMbZswOxmNitKZu6/NnX8TDZNictJe/7+ueNu8gLlRVAvdFrEJY7SWGY2OFk4y/L
JtOtTS78CXdLvtpAUgnc3ux9
-----END PRIVATE KEY-----"#;

struct HopProcess {
    child: Child,
    https_addr: SocketAddr,
    socks5_addr: SocketAddr,
    workdir: PathBuf,
}

impl Drop for HopProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

#[tokio::test]
async fn https_forward_proxy_tunnels_after_trusted_tls_and_cleans_up() {
    rove::tls::init_crypto();
    let hop = spawn_hop().await;
    let (target_addr, target_task) = start_echo_server().await;
    let mut client = connect_trusted_tls(hop.https_addr).await;

    let response = send_http_connect(&mut client, target_addr, USERNAME, PASSWORD).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected CONNECT response: {response}"
    );

    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");

    client.shutdown().await.unwrap();
    tokio::time::timeout(IO_TIMEOUT, target_task)
        .await
        .expect("target connection was not closed after the client disconnected")
        .expect("echo server task");
}

#[tokio::test]
async fn https_forward_proxy_rejects_untrusted_tls_bad_credentials_and_failed_upstream() {
    rove::tls::init_crypto();
    let hop = spawn_hop().await;

    let ready = connect_trusted_tls(hop.https_addr).await;
    drop(ready);

    let tcp = TcpStream::connect(hop.https_addr).await.unwrap();
    let untrusted = untrusted_tls_connector();
    assert!(
        untrusted.connect(server_name(), tcp).await.is_err(),
        "the HTTPS listener must reject a certificate chain outside the configured trust store"
    );

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let mut client = connect_trusted_tls(hop.https_addr).await;
    let response =
        send_http_connect(&mut client, target_addr, "wrong-user", "wrong-password").await;
    assert!(
        response.starts_with("HTTP/1.1 407"),
        "unexpected response for invalid credentials: {response}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), target.accept())
            .await
            .is_err(),
        "the target must not be dialed before proxy authentication succeeds"
    );

    let failed_target = format!("127.0.0.1:{}", unused_loopback_port());
    let mut client = connect_trusted_tls(hop.https_addr).await;
    let request = format!(
        "CONNECT {failed_target} HTTP/1.1\r\nHost: {failed_target}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        basic_token(USERNAME, PASSWORD)
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let response = read_http_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "unexpected response for an unavailable upstream: {response}"
    );
}

#[tokio::test]
async fn socks5_forward_proxy_tunnels_after_authentication() {
    rove::tls::init_crypto();
    let hop = spawn_hop().await;
    let (target_addr, target_task) = start_echo_server().await;

    let ready = connect_trusted_tls(hop.https_addr).await;
    drop(ready);
    let mut client = connect_tcp(hop.socks5_addr).await;
    open_socks5_tunnel(&mut client, target_addr, USERNAME, PASSWORD).await;

    client.write_all(b"pong").await.unwrap();
    let mut echoed = [0u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"pong");

    client.shutdown().await.unwrap();
    tokio::time::timeout(IO_TIMEOUT, target_task)
        .await
        .expect("target connection was not closed after the SOCKS5 client disconnected")
        .expect("echo server task");
}

#[tokio::test]
async fn a_listener_without_credentials_exits_instead_of_serving_an_open_proxy() {
    // The hop binary ships no fallback credential, so an operator who forgets
    // --username/--password must get a dead process rather than a listener that
    // anyone can use. Assert on the process, not just on argument parsing:
    // the whole point is that nothing ever binds.
    let port = unused_loopback_port();
    let addr = format!("127.0.0.1:{port}");
    let output = Command::new(env!("CARGO_BIN_EXE_rove-hop"))
        .arg("--socks5")
        .arg(&addr)
        .arg("--access-log-disable")
        .env_remove("Rove_HOP_USERNAME")
        .env_remove("Rove_HOP_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .expect("run rove-hop");

    assert!(!output.status.success(), "hop started without credentials");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hop listeners require credentials")
            && stderr.contains("--username")
            && stderr.contains("Rove_HOP_PASSWORD"),
        "startup failure must name the settings to fix: {stderr}"
    );
    assert!(
        std::net::TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(200))
            .is_err(),
        "hop left a listener bound on {addr} after refusing to start"
    );
}

async fn spawn_hop() -> HopProcess {
    let mut last = String::new();
    for attempt in 0..8 {
        match try_spawn_hop(attempt).await {
            Ok(hop) => return hop,
            Err(error) => last = error,
        }
    }
    panic!("rove-hop failed to start after retries: {last}");
}

async fn try_spawn_hop(attempt: u32) -> Result<HopProcess, String> {
    let https_addr = SocketAddr::from(([127, 0, 0, 1], unused_loopback_port()));
    let socks5_addr = SocketAddr::from(([127, 0, 0, 1], unused_loopback_port()));
    let workdir = std::env::temp_dir().join(format!(
        "rove-hop-it-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos(),
        attempt
    ));
    std::fs::create_dir_all(&workdir).map_err(|e| e.to_string())?;
    let cert = workdir.join("server.crt");
    let key = workdir.join("server.key");
    let stderr_path = workdir.join("rove-hop.err");
    std::fs::write(&cert, TEST_CERT).map_err(|e| e.to_string())?;
    std::fs::write(&key, TEST_KEY).map_err(|e| e.to_string())?;
    let stderr = std::fs::File::create(&stderr_path).map_err(|e| e.to_string())?;

    let child = Command::new(env!("CARGO_BIN_EXE_rove-hop"))
        .arg("--https")
        .arg(https_addr.to_string())
        .arg("--socks5")
        .arg(socks5_addr.to_string())
        .arg("--tls-cert")
        .arg(&cert)
        .arg("--tls-key")
        .arg(&key)
        .arg("--username")
        .arg(USERNAME)
        .arg("--password")
        .arg(PASSWORD)
        .arg("--access-log-disable")
        .arg("--log-level")
        .arg("warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .map_err(|e| e.to_string())?;

    let mut hop = HopProcess {
        child,
        https_addr,
        socks5_addr,
        workdir,
    };
    match wait_for_https(&mut hop).await {
        Ok(()) => Ok(hop),
        Err(error) => {
            let logs = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            Err(format!("{error}; stderr={logs}"))
        }
    }
}

async fn wait_for_https(hop: &mut HopProcess) -> Result<(), String> {
    let connector = trusted_tls_connector();
    let deadline = Instant::now() + START_TIMEOUT;
    let mut last_tls_error = None;
    loop {
        if let Some(status) = hop.child.try_wait().ok().flatten() {
            return Err(format!("rove-hop exited before HTTPS listen: {status}"));
        }
        if let Ok(tcp) = TcpStream::connect(hop.https_addr).await {
            match connector.connect(server_name(), tcp).await {
                Ok(_) => return Ok(()),
                Err(error) => last_tls_error = Some(error),
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "rove-hop HTTPS listener did not start within {START_TIMEOUT:?}: {last_tls_error:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn start_echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = [0u8; 4];
        socket.read_exact(&mut received).await.unwrap();
        socket.write_all(&received).await.unwrap();
        socket.read_to_end(&mut Vec::new()).await.unwrap();
    });
    (addr, task)
}

async fn connect_trusted_tls(addr: SocketAddr) -> TlsStream<TcpStream> {
    let connector = trusted_tls_connector();
    let deadline = Instant::now() + START_TIMEOUT;
    let mut last_tls_error = None;

    loop {
        if let Ok(tcp) = TcpStream::connect(addr).await {
            match connector.connect(server_name(), tcp).await {
                Ok(stream) => return stream,
                Err(error) => last_tls_error = Some(error),
            }
        }
        assert!(
            Instant::now() < deadline,
            "rove-hop HTTPS listener did not start within {START_TIMEOUT:?}: {last_tls_error:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn connect_tcp(addr: SocketAddr) -> TcpStream {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if let Ok(stream) = TcpStream::connect(addr).await {
            return stream;
        }
        assert!(
            Instant::now() < deadline,
            "rove-hop SOCKS5 listener did not start within {START_TIMEOUT:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn send_http_connect<S>(
    stream: &mut S,
    target: SocketAddr,
    username: &str,
    password: &str,
) -> String
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        basic_token(username, password)
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    read_http_head(stream).await
}

async fn read_http_head<S>(stream: &mut S) -> String
where
    S: AsyncRead + Unpin,
{
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
        assert!(
            head.len() <= 8192,
            "HTTP response head exceeded the test limit"
        );
        if head.ends_with(b"\r\n\r\n") {
            return String::from_utf8(head).expect("HTTP response must be UTF-8");
        }
    }
}

async fn open_socks5_tunnel(
    client: &mut TcpStream,
    target: SocketAddr,
    username: &str,
    password: &str,
) {
    client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x02]);

    let mut auth = Vec::with_capacity(3 + username.len() + password.len());
    auth.push(0x01);
    auth.push(username.len() as u8);
    auth.extend_from_slice(username.as_bytes());
    auth.push(password.len() as u8);
    auth.extend_from_slice(password.as_bytes());
    client.write_all(&auth).await.unwrap();
    let mut auth_response = [0u8; 2];
    client.read_exact(&mut auth_response).await.unwrap();
    assert_eq!(auth_response, [0x01, 0x00]);

    let SocketAddr::V4(target) = target else {
        panic!("test echo server must use IPv4");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut response = [0u8; 10];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response[0], 0x05);
    assert_eq!(response[1], 0x00, "SOCKS5 CONNECT must succeed");
}

fn trusted_tls_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(TEST_CA.as_bytes()) {
        roots.add(cert.expect("parse rove-hop test CA")).unwrap();
    }
    assert!(!roots.is_empty(), "rove-hop test CA must contain a root");
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn untrusted_tls_connector() -> TlsConnector {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn server_name() -> ServerName<'static> {
    ServerName::try_from("localhost")
        .expect("parse test server name")
        .to_owned()
}

fn basic_token(username: &str, password: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
}

fn unused_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("read reserved loopback port")
        .port()
}
