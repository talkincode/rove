use std::cmp;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use rove::inbound::tuic::codec::{cmd, Address, VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const DEFAULT_UUID: &str = "01010101-0101-0101-0101-010101010101";
const DEFAULT_PASSWORD: &str = "tuic-bench";
const CHUNK: &[u8] = &[b'x'; 256 * 1024];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenchmarkPath {
    Local,
    ReverseIngress,
}

impl BenchmarkPath {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "local" => Ok(BenchmarkPath::Local),
            "reverse-ingress" | "ingress" => Ok(BenchmarkPath::ReverseIngress),
            other => anyhow::bail!("unknown --path {other:?}; expected local or reverse-ingress"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            BenchmarkPath::Local => "local",
            BenchmarkPath::ReverseIngress => "reverse-ingress",
        }
    }

    fn default_addr(self) -> &'static str {
        match self {
            BenchmarkPath::Local => "127.0.0.1:10443",
            BenchmarkPath::ReverseIngress => "127.0.0.1:30443",
        }
    }
}

#[derive(Debug, Clone)]
struct Args {
    path: BenchmarkPath,
    tuic_addr: String,
    server_name: String,
    uuid: String,
    password: String,
    target_host: String,
    target_bind: String,
    target_port: u16,
    requests: usize,
    concurrency: usize,
    mib: usize,
    streams: usize,
    timeout: Duration,
    alpn: String,
    directions: Vec<String>,
}

#[derive(Debug)]
struct ResultSample {
    ok: bool,
    latency_ms: f64,
    bytes_count: usize,
    error: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rove::tls::init_crypto();
    let args = Args::parse()?;
    let _server = start_target(&args.target_bind, args.target_port, args.mib * 1024 * 1024).await?;

    let conn = connect_and_authenticate(&args).await?;
    run_latency(&args, conn.clone()).await;
    for direction in &args.directions {
        run_bandwidth(&args, conn.clone(), direction).await;
    }
    conn.close(0u32.into(), b"benchmark done");
    Ok(())
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let mut parsed = Args {
            path: BenchmarkPath::Local,
            tuic_addr: "127.0.0.1:10443".to_string(),
            server_name: "localhost".to_string(),
            uuid: DEFAULT_UUID.to_string(),
            password: DEFAULT_PASSWORD.to_string(),
            target_host: "host.docker.internal".to_string(),
            target_bind: "0.0.0.0".to_string(),
            target_port: 19092,
            requests: 2000,
            concurrency: 20,
            mib: 256,
            streams: 1,
            timeout: Duration::from_secs(30),
            alpn: "h3".to_string(),
            directions: vec!["download".to_string(), "upload".to_string()],
        };

        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let mut tuic_addr_explicit = false;
        let mut i = 0;
        while i < args.len() {
            let key = args[i].as_str();
            let value = |i: &mut usize| -> anyhow::Result<String> {
                *i += 1;
                args.get(*i)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("{key} requires a value"))
            };
            match key {
                "--path" => parsed.path = BenchmarkPath::parse(&value(&mut i)?)?,
                "--tuic-addr" => {
                    parsed.tuic_addr = value(&mut i)?;
                    tuic_addr_explicit = true;
                }
                "--server-name" => parsed.server_name = value(&mut i)?,
                "--uuid" => parsed.uuid = value(&mut i)?,
                "--password" => parsed.password = value(&mut i)?,
                "--target-host" => parsed.target_host = value(&mut i)?,
                "--target-bind" => parsed.target_bind = value(&mut i)?,
                "--target-port" => parsed.target_port = value(&mut i)?.parse()?,
                "--requests" => parsed.requests = value(&mut i)?.parse()?,
                "--concurrency" => parsed.concurrency = value(&mut i)?.parse()?,
                "--mib" => parsed.mib = value(&mut i)?.parse()?,
                "--streams" => parsed.streams = value(&mut i)?.parse()?,
                "--timeout" => {
                    let secs: f64 = value(&mut i)?.parse()?;
                    parsed.timeout = Duration::from_secs_f64(secs);
                }
                "--alpn" => parsed.alpn = value(&mut i)?,
                "--directions" => {
                    parsed.directions = value(&mut i)?
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument {other:?}; pass --help for usage"),
            }
            i += 1;
        }
        if !tuic_addr_explicit {
            parsed.tuic_addr = parsed.path.default_addr().to_string();
        }
        anyhow::ensure!(parsed.concurrency > 0, "--concurrency must be > 0");
        anyhow::ensure!(parsed.streams > 0, "--streams must be > 0");
        Ok(parsed)
    }
}

fn print_usage() {
    println!(
        "Usage: cargo run --release --example tuic-benchmark-local -- [options]\n\
         Options:\n\
           --path PATH                local (default) | reverse-ingress\n\
           --tuic-addr HOST:PORT      override path default (10443 local / 30443 relay)\n\
           --uuid UUID               default {DEFAULT_UUID}\n\
           --password PASSWORD       default {DEFAULT_PASSWORD}\n\
           --target-host HOST        default host.docker.internal\n\
           --target-port PORT        default 19092\n\
           --requests N              latency requests, default 2000\n\
           --concurrency N           latency concurrency, default 20\n\
           --mib N                   MiB per stream for bandwidth, default 256\n\
           --streams N               concurrent bandwidth streams, default 1\n\
           --directions LIST         download,upload by default"
    );
}

async fn connect_and_authenticate(args: &Args) -> anyhow::Result<quinn::Connection> {
    let endpoint = client_endpoint(&args.alpn)?;
    let remote: SocketAddr = args
        .tuic_addr
        .parse()
        .with_context(|| format!("parse --tuic-addr {}", args.tuic_addr))?;
    let conn = tokio::time::timeout(
        args.timeout,
        endpoint
            .connect(remote, &args.server_name)
            .context("start QUIC connect")?,
    )
    .await
    .context("TUIC QUIC connect timed out")?
    .context("TUIC QUIC connect failed")?;

    let uuid = parse_uuid(&args.uuid)?;
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, &uuid, args.password.as_bytes())
        .map_err(|_| anyhow::anyhow!("export TUIC token"))?;
    let mut msg = vec![VERSION, cmd::AUTHENTICATE];
    msg.extend_from_slice(&uuid);
    msg.extend_from_slice(&token);
    let mut uni = conn.open_uni().await.context("open authenticate stream")?;
    uni.write_all(&msg).await.context("write authenticate")?;
    uni.finish().context("finish authenticate stream")?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(conn)
}

fn client_endpoint(alpn: &str) -> anyhow::Result<quinn::Endpoint> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .context("build QUIC rustls client config")?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(qc));
    let mut tr = quinn::TransportConfig::default();
    tr.datagram_receive_buffer_size(Some(1024 * 1024));
    tr.datagram_send_buffer_size(1024 * 1024);
    cfg.transport_config(Arc::new(tr));
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

#[derive(Debug)]
struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn parse_uuid(input: &str) -> anyhow::Result<[u8; 16]> {
    let hex = input.chars().filter(|c| *c != '-').collect::<String>();
    anyhow::ensure!(hex.len() == 32, "UUID must contain 32 hex digits");
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

async fn start_target(bind: &str, port: u16, payload_bytes: usize) -> anyhow::Result<SocketAddr> {
    let addr = format!("{bind}:{port}");
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind target server {addr}"))?;
    let bound = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle_target(stream, payload_bytes));
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(bound)
}

async fn handle_target(mut stream: TcpStream, payload_bytes: usize) {
    let Ok((head, body)) = read_http_head_and_remainder(&mut stream).await else {
        return;
    };
    let request_line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    if request_line.starts_with(b"GET ") {
        let response_body: &[u8] = if request_line.starts_with(b"GET / ") {
            b"rove-local-benchmark\n"
        } else {
            &CHUNK[..0]
        };
        let response_len = if request_line.starts_with(b"GET / ") {
            response_body.len()
        } else {
            payload_bytes
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {response_len}\r\nConnection: close\r\n\r\n"
        );
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        if !response_body.is_empty() {
            let _ = stream.write_all(response_body).await;
        } else {
            let mut remaining = payload_bytes;
            while remaining > 0 {
                let n = cmp::min(remaining, CHUNK.len());
                if stream.write_all(&CHUNK[..n]).await.is_err() {
                    return;
                }
                remaining -= n;
            }
        }
        let _ = stream.flush().await;
    } else if request_line.starts_with(b"POST ") {
        let mut remaining = parse_content_length(&head).saturating_sub(body.len());
        while remaining > 0 {
            let mut buf = vec![0u8; cmp::min(remaining, CHUNK.len())];
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => remaining -= n,
            }
        }
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await;
    }
}

async fn run_latency(args: &Args, conn: quinn::Connection) {
    let sem = Arc::new(Semaphore::new(args.concurrency));
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(args.requests);
    for _ in 0..args.requests {
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        let conn = conn.clone();
        let args = args.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            one_request(&args, conn).await
        }));
    }
    let mut results = Vec::with_capacity(args.requests);
    for task in tasks {
        results.push(task.await.unwrap_or_else(|e| ResultSample {
            ok: false,
            latency_ms: 0.0,
            bytes_count: 0,
            error: e.to_string(),
        }));
    }
    let elapsed = started.elapsed().as_secs_f64();
    print_latency(args, elapsed, &results);
}

async fn one_request(args: &Args, conn: quinn::Connection) -> ResultSample {
    let started = Instant::now();
    match tokio::time::timeout(args.timeout, one_http_get(args, conn)).await {
        Ok(Ok(bytes_count)) => ResultSample {
            ok: true,
            latency_ms: started.elapsed().as_secs_f64() * 1000.0,
            bytes_count,
            error: String::new(),
        },
        Ok(Err(e)) => ResultSample {
            ok: false,
            latency_ms: started.elapsed().as_secs_f64() * 1000.0,
            bytes_count: 0,
            error: e.to_string(),
        },
        Err(_) => ResultSample {
            ok: false,
            latency_ms: started.elapsed().as_secs_f64() * 1000.0,
            bytes_count: 0,
            error: "timeout".to_string(),
        },
    }
}

async fn one_http_get(args: &Args, conn: quinn::Connection) -> anyhow::Result<usize> {
    let (mut send, mut recv) = open_tuic_connect(args, conn).await?;
    let target = format!("{}:{}", args.target_host, args.target_port);
    send.write_all(
        format!("GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let (head, body) = read_quic_http_head_and_remainder(&mut recv).await?;
    let expected = parse_content_length(&head);
    let received = read_body_to_expected(&mut recv, body.len(), expected).await?;
    let _ = send.finish();
    anyhow::ensure!(
        received == expected,
        "read {received} bytes, expected {expected}"
    );
    Ok(received)
}

async fn run_bandwidth(args: &Args, conn: quinn::Connection, direction: &str) {
    let payload_bytes = args.mib * 1024 * 1024;
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(args.streams);
    for _ in 0..args.streams {
        let args = args.clone();
        let conn = conn.clone();
        let direction = direction.to_string();
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            let result = if direction == "download" {
                download_once(&args, conn, payload_bytes).await
            } else {
                upload_once(&args, conn, payload_bytes).await
            };
            match result {
                Ok(bytes_count) => ResultSample {
                    ok: true,
                    latency_ms: started.elapsed().as_secs_f64() * 1000.0,
                    bytes_count,
                    error: String::new(),
                },
                Err(e) => ResultSample {
                    ok: false,
                    latency_ms: started.elapsed().as_secs_f64() * 1000.0,
                    bytes_count: 0,
                    error: e.to_string(),
                },
            }
        }));
    }
    let mut results = Vec::with_capacity(args.streams);
    for task in tasks {
        results.push(task.await.unwrap());
    }
    let elapsed = started.elapsed().as_secs_f64();
    print_bandwidth(args, direction, elapsed, &results);
}

async fn download_once(
    args: &Args,
    conn: quinn::Connection,
    payload_bytes: usize,
) -> anyhow::Result<usize> {
    one_http_get_with_path(args, conn, "/download", payload_bytes).await
}

async fn one_http_get_with_path(
    args: &Args,
    conn: quinn::Connection,
    path: &str,
    payload_bytes: usize,
) -> anyhow::Result<usize> {
    let (mut send, mut recv) = open_tuic_connect(args, conn).await?;
    let target = format!("{}:{}", args.target_host, args.target_port);
    send.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let (head, body) = read_quic_http_head_and_remainder(&mut recv).await?;
    let expected = parse_content_length(&head);
    let received = read_body_to_expected(&mut recv, body.len(), expected).await?;
    let _ = send.finish();
    anyhow::ensure!(
        received == payload_bytes,
        "downloaded {received} bytes, expected {payload_bytes}"
    );
    Ok(received)
}

async fn upload_once(
    args: &Args,
    conn: quinn::Connection,
    payload_bytes: usize,
) -> anyhow::Result<usize> {
    let (mut send, mut recv) = open_tuic_connect(args, conn).await?;
    let target = format!("{}:{}", args.target_host, args.target_port);
    send.write_all(
        format!(
            "POST /upload HTTP/1.1\r\nHost: {target}\r\nContent-Length: {payload_bytes}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await?;
    let mut remaining = payload_bytes;
    while remaining > 0 {
        let n = cmp::min(remaining, CHUNK.len());
        send.write_all(&CHUNK[..n]).await?;
        remaining -= n;
    }
    send.finish()?;
    let head = read_quic_http_head(&mut recv).await?;
    anyhow::ensure!(
        head.starts_with(b"HTTP/1.1 200"),
        "bad upload response: {}",
        String::from_utf8_lossy(&head)
    );
    Ok(payload_bytes)
}

async fn open_tuic_connect(
    args: &Args,
    conn: quinn::Connection,
) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, recv) = conn.open_bi().await.context("open TUIC bi stream")?;
    let mut msg = vec![VERSION, cmd::CONNECT];
    Address::from_host_port(&args.target_host, args.target_port).encode(&mut msg);
    send.write_all(&msg).await.context("write TUIC CONNECT")?;
    Ok((send, recv))
}

async fn read_body_to_expected(
    recv: &mut quinn::RecvStream,
    mut received: usize,
    expected: usize,
) -> anyhow::Result<usize> {
    let mut buf = vec![0u8; 256 * 1024];
    while received < expected {
        match recv.read(&mut buf).await? {
            Some(0) | None => break,
            Some(n) => received += n,
        }
    }
    Ok(received)
}

async fn read_quic_http_head(recv: &mut quinn::RecvStream) -> anyhow::Result<Vec<u8>> {
    let (head, _) = read_quic_http_head_and_remainder(recv).await?;
    Ok(head)
}

async fn read_quic_http_head_and_remainder(
    recv: &mut quinn::RecvStream,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::new();
    let mut buf = vec![0u8; 4096];
    while !data.windows(4).any(|w| w == b"\r\n\r\n") {
        match recv.read(&mut buf).await? {
            Some(0) | None => break,
            Some(n) => data.extend_from_slice(&buf[..n]),
        }
        anyhow::ensure!(data.len() <= 64 * 1024, "HTTP head too large");
    }
    let marker = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(data.len());
    Ok((data[..marker].to_vec(), data[marker..].to_vec()))
}

async fn read_http_head_and_remainder(
    stream: &mut TcpStream,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::new();
    while !data.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        anyhow::ensure!(data.len() <= 64 * 1024, "HTTP head too large");
    }
    let marker = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(data.len());
    Ok((data[..marker].to_vec(), data[marker..].to_vec()))
}

fn parse_content_length(head: &[u8]) -> usize {
    for line in head.split(|b| *b == b'\n') {
        let line = String::from_utf8_lossy(line);
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            return value.trim().parse().unwrap_or(0);
        }
    }
    0
}

fn print_latency(args: &Args, elapsed: f64, results: &[ResultSample]) {
    let oks = results
        .iter()
        .filter(|r| r.ok)
        .map(|r| r.latency_ms)
        .collect::<Vec<_>>();
    let failures = results.iter().filter(|r| !r.ok).collect::<Vec<_>>();
    println!("\nmode=tuic path={}", args.path.as_str());
    println!(
        "  requests={} concurrency={} elapsed={elapsed:.3}s",
        args.requests, args.concurrency
    );
    println!(
        "  ok={} failed={} rps={:.1}",
        oks.len(),
        failures.len(),
        oks.len() as f64 / elapsed
    );
    if !oks.is_empty() {
        println!(
            "  latency_ms min={:.2} p50={:.2} p95={:.2} p99={:.2} max={:.2}",
            percentile(&oks, 0.0),
            percentile(&oks, 0.50),
            percentile(&oks, 0.95),
            percentile(&oks, 0.99),
            percentile(&oks, 1.0)
        );
    }
    if let Some(first) = failures.first() {
        println!("  first_error={}", first.error);
    }
}

fn print_bandwidth(args: &Args, direction: &str, elapsed: f64, results: &[ResultSample]) {
    let ok = results.iter().filter(|r| r.ok).collect::<Vec<_>>();
    let failed = results.iter().filter(|r| !r.ok).collect::<Vec<_>>();
    let total_bytes = ok.iter().map(|r| r.bytes_count).sum::<usize>();
    let mib = total_bytes as f64 / 1024.0 / 1024.0;
    let mibs = mib / elapsed;
    let mbps = total_bytes as f64 * 8.0 / elapsed / 1_000_000.0;
    println!(
        "\nmode=tuic path={} direction={direction}",
        args.path.as_str()
    );
    println!(
        "  streams={} payload_per_stream={}MiB elapsed={elapsed:.3}s",
        args.streams, args.mib
    );
    println!(
        "  ok={} failed={} throughput={mibs:.1}MiB/s {mbps:.1}Mbit/s",
        ok.len(),
        failed.len()
    );
    if let Some(first) = failed.first() {
        println!("  first_error={}", first.error);
    }
}

fn percentile(values: &[f64], ratio: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(|a, b| a.total_cmp(b));
    let idx = if ratio <= 0.0 {
        0
    } else {
        ((ordered.len() as f64 * ratio).ceil() as usize).saturating_sub(1)
    };
    ordered[idx.min(ordered.len() - 1)]
}

#[allow(dead_code)]
fn _v4_addr(host: &str, port: u16) -> Address {
    host.parse::<Ipv4Addr>()
        .map(|ip| Address::V4(ip, port))
        .unwrap_or_else(|_| Address::Domain(host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_path_selects_expected_local_port() {
        assert_eq!(BenchmarkPath::Local.default_addr(), "127.0.0.1:10443");
        assert_eq!(
            BenchmarkPath::parse("reverse-ingress")
                .unwrap()
                .default_addr(),
            "127.0.0.1:30443"
        );
        assert!(BenchmarkPath::parse("reverse").is_err());
    }
}
