//! Local Docker-stack proxy benchmark: one Rust load generator for the
//! TCP-based inbound protocols (HTTP CONNECT plain / over TLS, SOCKS5 plain /
//! over TLS) crossed with each ingress path (local listener or public
//! reverse-ingress relay) and every egress mode the local snapshot defines
//! (direct, https hop, socks5 hop, socks5-tls hop, reverse hop).
//!
//! Replaces the retired Python scripts (`benchmark-local.py`,
//! `bandwidth-local.py`) with a client that cannot bottleneck a Rust data
//! plane, and adds what they lacked: warmup, per-phase latency breakdown
//! (TCP connect / TLS handshake / tunnel establish / request), optional
//! open-loop mode at a fixed arrival rate, a concurrency sweep, a rate-limit
//! accuracy check for the throttled path, and a `max_connections` probe.
//!
//! Usage (docker compose stack up, certs generated):
//!
//! ```text
//! cargo run --release --example proxy-benchmark-local -- latency
//! cargo run --release --example proxy-benchmark-local -- bandwidth --mib 256 --streams 1
//! cargo run --release --example proxy-benchmark-local -- sweep --concurrency-steps 1,8,32,128
//! cargo run --release --example proxy-benchmark-local -- limits
//! cargo run --release --example proxy-benchmark-local -- latency \
//!   --paths local,reverse-ingress
//! cargo run --release --example proxy-benchmark-local -- all --json-out /tmp/rove-bench.json
//! ```

use std::cmp;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine as _;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::ServerName;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;

use rove::io::IoStream;

const PASSWORD: &str = "bench";
const CHUNK: &[u8] = &[b'x'; 256 * 1024];

// ---------------------------------------------------------------------------
// Inbound / egress matrix
// ---------------------------------------------------------------------------

/// Inbound listener protocols on the local `rove-local-main` container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Inbound {
    Http,
    HttpsTls,
    Socks5,
    Socks5Tls,
}

impl Inbound {
    const ALL: [Inbound; 4] = [
        Inbound::Http,
        Inbound::HttpsTls,
        Inbound::Socks5,
        Inbound::Socks5Tls,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Inbound::Http => "http",
            Inbound::HttpsTls => "https-tls",
            Inbound::Socks5 => "socks5",
            Inbound::Socks5Tls => "socks5-tls",
        }
    }

    fn parse(input: &str) -> anyhow::Result<Self> {
        match input {
            "http" => Ok(Inbound::Http),
            "https-tls" => Ok(Inbound::HttpsTls),
            "socks5" => Ok(Inbound::Socks5),
            "socks5-tls" => Ok(Inbound::Socks5Tls),
            other => anyhow::bail!(
                "unknown inbound {other:?}; expected http, https-tls, socks5 or socks5-tls"
            ),
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Inbound::Http => 18080,
            Inbound::HttpsTls => 18443,
            Inbound::Socks5 => 11080,
            Inbound::Socks5Tls => 11081,
        }
    }

    fn tls(self) -> bool {
        matches!(self, Inbound::HttpsTls | Inbound::Socks5Tls)
    }
}

/// How the load generator reaches the same Rove listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum IngressPath {
    Local,
    ReverseIngress,
}

impl IngressPath {
    fn as_str(self) -> &'static str {
        match self {
            IngressPath::Local => "local",
            IngressPath::ReverseIngress => "reverse-ingress",
        }
    }

    fn parse(input: &str) -> anyhow::Result<Self> {
        match input {
            "local" => Ok(IngressPath::Local),
            "reverse-ingress" | "ingress" => Ok(IngressPath::ReverseIngress),
            other => anyhow::bail!("unknown path {other:?}; expected local or reverse-ingress"),
        }
    }
}

/// Egress modes, keyed by the benchmark users in `docker/local/snapshot.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Mode {
    Direct,
    Https,
    Socks5,
    Socks5Tls,
    Reverse,
    /// Failover chain whose reverse primary is healthy: every tunnel wins on
    /// the first member, measuring chain bookkeeping overhead vs `Reverse`.
    Chain,
    /// Failover chain whose reverse primary is never registered: every tunnel
    /// fails over to the socks5 backup during establishment, measuring the
    /// per-connection failover cost (issue #17 acceptance).
    ChainFailover,
    Limited,
}

impl Mode {
    const DEFAULT: [Mode; 7] = [
        Mode::Direct,
        Mode::Https,
        Mode::Socks5,
        Mode::Socks5Tls,
        Mode::Reverse,
        Mode::Chain,
        Mode::ChainFailover,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Mode::Direct => "direct",
            Mode::Https => "https",
            Mode::Socks5 => "socks5",
            Mode::Socks5Tls => "socks5tls",
            Mode::Reverse => "reverse",
            Mode::Chain => "chain",
            Mode::ChainFailover => "chain-failover",
            Mode::Limited => "limited",
        }
    }

    fn parse(input: &str) -> anyhow::Result<Self> {
        match input {
            "direct" => Ok(Mode::Direct),
            "https" => Ok(Mode::Https),
            "socks5" => Ok(Mode::Socks5),
            "socks5tls" => Ok(Mode::Socks5Tls),
            "reverse" => Ok(Mode::Reverse),
            "chain" => Ok(Mode::Chain),
            "chain-failover" | "chainfailover" => Ok(Mode::ChainFailover),
            "limited" => Ok(Mode::Limited),
            other => anyhow::bail!(
                "unknown mode {other:?}; expected direct, https, socks5, socks5tls, reverse, chain, chain-failover or limited"
            ),
        }
    }

    fn username(self) -> &'static str {
        match self {
            Mode::Direct => "bench-direct",
            Mode::Https => "bench-https",
            Mode::Socks5 => "bench-socks5",
            Mode::Socks5Tls => "bench-socks5tls",
            Mode::Reverse => "bench-reverse",
            Mode::Chain => "bench-chain",
            Mode::ChainFailover => "bench-chain-failover",
            Mode::Limited => "bench-limited",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Direction {
    Download,
    Upload,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Download => "download",
            Direction::Upload => "upload",
        }
    }

    fn parse(input: &str) -> anyhow::Result<Self> {
        match input {
            "download" => Ok(Direction::Download),
            "upload" => Ok(Direction::Upload),
            other => anyhow::bail!("unknown direction {other:?}; expected download or upload"),
        }
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    Latency,
    Bandwidth,
    Sweep,
    Limits,
    All,
}

#[derive(Debug, Clone)]
struct Args {
    command: Command,
    proxy_host: String,
    http_port: u16,
    https_port: u16,
    socks5_port: u16,
    socks5tls_port: u16,
    ingress_http_port: u16,
    ingress_https_port: u16,
    ingress_socks5_port: u16,
    ingress_socks5tls_port: u16,
    tls_server_name: String,
    ca_cert: Option<PathBuf>,
    insecure_tls: bool,
    target_host: String,
    target_bind: String,
    target_port: u16,
    inbounds: Vec<Inbound>,
    paths: Vec<IngressPath>,
    modes: Vec<Mode>,
    directions: Vec<Direction>,
    requests: usize,
    concurrency: usize,
    warmup: usize,
    rate: Option<f64>,
    mib: usize,
    streams: usize,
    concurrency_steps: Vec<usize>,
    timeout: Duration,
    stats: bool,
    stats_interval: Duration,
    stats_containers: Vec<String>,
    json_out: Option<PathBuf>,
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let argv = std::env::args().skip(1).collect::<Vec<_>>();
        let command = match argv.first().map(String::as_str) {
            Some("latency") => Command::Latency,
            Some("bandwidth") => Command::Bandwidth,
            Some("sweep") => Command::Sweep,
            Some("limits") => Command::Limits,
            Some("all") => Command::All,
            Some("-h") | Some("--help") => {
                print_usage();
                std::process::exit(0);
            }
            Some(other) => anyhow::bail!(
                "unknown command {other:?}; expected latency, bandwidth, sweep, limits or all"
            ),
            None => {
                print_usage();
                std::process::exit(2);
            }
        };

        let mut parsed = Args {
            command,
            proxy_host: "127.0.0.1".to_string(),
            http_port: Inbound::Http.default_port(),
            https_port: Inbound::HttpsTls.default_port(),
            socks5_port: Inbound::Socks5.default_port(),
            socks5tls_port: Inbound::Socks5Tls.default_port(),
            ingress_http_port: 38080,
            ingress_https_port: 38443,
            ingress_socks5_port: 31080,
            ingress_socks5tls_port: 31081,
            tls_server_name: "localhost".to_string(),
            ca_cert: default_ca_cert(),
            insecure_tls: false,
            target_host: "host.docker.internal".to_string(),
            target_bind: "0.0.0.0".to_string(),
            target_port: 19090,
            inbounds: Inbound::ALL.to_vec(),
            paths: vec![IngressPath::Local],
            modes: Mode::DEFAULT.to_vec(),
            directions: vec![Direction::Download, Direction::Upload],
            requests: 2000,
            concurrency: 20,
            warmup: 100,
            rate: None,
            mib: 256,
            streams: 1,
            concurrency_steps: vec![1, 8, 32, 128],
            timeout: Duration::from_secs(30),
            stats: false,
            stats_interval: Duration::from_millis(500),
            stats_containers: vec![
                "rove-local-main".to_string(),
                "rove-local-hop-https".to_string(),
                "rove-local-hop-socks5".to_string(),
                "rove-local-hop-socks5tls".to_string(),
                "rove-local-hop-reverse".to_string(),
                "rove-local-relay-ingress".to_string(),
            ],
            json_out: None,
        };

        let mut i = 1;
        while i < argv.len() {
            let key = argv[i].as_str();
            let value = |i: &mut usize| -> anyhow::Result<String> {
                *i += 1;
                argv.get(*i)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("{key} requires a value"))
            };
            match key {
                "--proxy-host" => parsed.proxy_host = value(&mut i)?,
                "--http-port" => parsed.http_port = value(&mut i)?.parse()?,
                "--https-port" => parsed.https_port = value(&mut i)?.parse()?,
                "--socks5-port" => parsed.socks5_port = value(&mut i)?.parse()?,
                "--socks5tls-port" => parsed.socks5tls_port = value(&mut i)?.parse()?,
                "--ingress-http-port" => parsed.ingress_http_port = value(&mut i)?.parse()?,
                "--ingress-https-port" => parsed.ingress_https_port = value(&mut i)?.parse()?,
                "--ingress-socks5-port" => parsed.ingress_socks5_port = value(&mut i)?.parse()?,
                "--ingress-socks5tls-port" => {
                    parsed.ingress_socks5tls_port = value(&mut i)?.parse()?
                }
                "--tls-server-name" => parsed.tls_server_name = value(&mut i)?,
                "--ca-cert" => parsed.ca_cert = Some(PathBuf::from(value(&mut i)?)),
                "--insecure-tls" => parsed.insecure_tls = true,
                "--target-host" => parsed.target_host = value(&mut i)?,
                "--target-bind" => parsed.target_bind = value(&mut i)?,
                "--target-port" => parsed.target_port = value(&mut i)?.parse()?,
                "--inbounds" => parsed.inbounds = parse_csv(&value(&mut i)?, Inbound::parse)?,
                "--paths" => {
                    parsed.paths = parse_csv(&value(&mut i)?, IngressPath::parse)?;
                }
                "--modes" => parsed.modes = parse_csv(&value(&mut i)?, Mode::parse)?,
                "--directions" => {
                    parsed.directions = parse_csv(&value(&mut i)?, Direction::parse)?;
                }
                "--requests" => parsed.requests = value(&mut i)?.parse()?,
                "--concurrency" => parsed.concurrency = value(&mut i)?.parse()?,
                "--warmup" => parsed.warmup = value(&mut i)?.parse()?,
                "--rate" => parsed.rate = Some(value(&mut i)?.parse()?),
                "--mib" => parsed.mib = value(&mut i)?.parse()?,
                "--streams" => parsed.streams = value(&mut i)?.parse()?,
                "--concurrency-steps" => {
                    parsed.concurrency_steps =
                        parse_csv(&value(&mut i)?, |s| Ok(s.parse::<usize>()?))?;
                }
                "--timeout" => {
                    let secs: f64 = value(&mut i)?.parse()?;
                    parsed.timeout = Duration::from_secs_f64(secs);
                }
                "--stats" => parsed.stats = true,
                "--stats-interval" => {
                    let secs: f64 = value(&mut i)?.parse()?;
                    parsed.stats_interval = Duration::from_secs_f64(secs);
                }
                "--stats-containers" => {
                    parsed.stats_containers = parse_csv(&value(&mut i)?, |s| Ok(s.to_string()))?;
                }
                "--json-out" => parsed.json_out = Some(PathBuf::from(value(&mut i)?)),
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument {other:?}; pass --help for usage"),
            }
            i += 1;
        }

        anyhow::ensure!(!parsed.inbounds.is_empty(), "--inbounds cannot be empty");
        anyhow::ensure!(!parsed.paths.is_empty(), "--paths cannot be empty");
        anyhow::ensure!(!parsed.modes.is_empty(), "--modes cannot be empty");
        anyhow::ensure!(
            !parsed.directions.is_empty(),
            "--directions cannot be empty"
        );
        anyhow::ensure!(parsed.requests > 0, "--requests must be > 0");
        anyhow::ensure!(parsed.concurrency > 0, "--concurrency must be > 0");
        anyhow::ensure!(parsed.streams > 0, "--streams must be > 0");
        anyhow::ensure!(
            !parsed.concurrency_steps.is_empty() && parsed.concurrency_steps.iter().all(|c| *c > 0),
            "--concurrency-steps must be non-empty positive integers"
        );
        if let Some(rate) = parsed.rate {
            anyhow::ensure!(rate > 0.0, "--rate must be > 0");
        }
        Ok(parsed)
    }

    fn inbound_port(&self, path: IngressPath, inbound: Inbound) -> u16 {
        match (path, inbound) {
            (IngressPath::Local, Inbound::Http) => self.http_port,
            (IngressPath::Local, Inbound::HttpsTls) => self.https_port,
            (IngressPath::Local, Inbound::Socks5) => self.socks5_port,
            (IngressPath::Local, Inbound::Socks5Tls) => self.socks5tls_port,
            (IngressPath::ReverseIngress, Inbound::Http) => self.ingress_http_port,
            (IngressPath::ReverseIngress, Inbound::HttpsTls) => self.ingress_https_port,
            (IngressPath::ReverseIngress, Inbound::Socks5) => self.ingress_socks5_port,
            (IngressPath::ReverseIngress, Inbound::Socks5Tls) => self.ingress_socks5tls_port,
        }
    }
}

fn default_ca_cert() -> Option<PathBuf> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docker/local/certs/local-rove-ca.crt");
    path.exists().then_some(path)
}

fn print_usage() {
    println!(
        "Usage: cargo run --release --example proxy-benchmark-local -- COMMAND [options]\n\
         \n\
         Commands:\n\
           latency     tunnel latency matrix (inbound x mode), warmup + phase breakdown\n\
           bandwidth   tunnel throughput (download/upload) per inbound x mode\n\
           sweep       latency/RPS across --concurrency-steps (http inbound by default)\n\
           limits      rate-limit accuracy + max_connections probe (bench-limited user)\n\
           all         latency + bandwidth + sweep + limits\n\
         \n\
         Connection options:\n\
           --proxy-host HOST         default 127.0.0.1\n\
           --http-port PORT          default 18080\n\
           --https-port PORT         default 18443\n\
           --socks5-port PORT        default 11080\n\
           --socks5tls-port PORT     default 11081\n\
           --paths LIST              local (default), reverse-ingress, or both\n\
           --ingress-http-port PORT  reverse-ingress HTTP, default 38080\n\
           --ingress-https-port PORT reverse-ingress HTTPS, default 38443\n\
           --ingress-socks5-port PORT       reverse-ingress SOCKS5, default 31080\n\
           --ingress-socks5tls-port PORT    reverse-ingress SOCKS5-TLS, default 31081\n\
           --tls-server-name NAME    SNI for TLS inbounds, default localhost\n\
           --ca-cert PATH            trust anchor for TLS inbounds,\n\
                                     default docker/local/certs/local-rove-ca.crt\n\
           --insecure-tls            skip TLS certificate verification\n\
           --target-host HOST        default host.docker.internal\n\
           --target-bind ADDR        default 0.0.0.0\n\
           --target-port PORT        default 19090\n\
         \n\
         Workload options:\n\
           --inbounds LIST           default http,https-tls,socks5,socks5-tls\n\
           --modes LIST              default direct,https,socks5,socks5tls,reverse,\n\
                                     chain,chain-failover\n\
           --directions LIST         default download,upload\n\
           --requests N              latency requests per case, default 2000\n\
           --concurrency N           closed-loop worker cap, default 20\n\
           --warmup N                unreported warmup requests per case, default 100\n\
           --rate RPS                open-loop arrival rate (fixed schedule) instead of\n\
                                     closed-loop; latency then includes queue wait\n\
           --mib N                   MiB per bandwidth stream, default 256\n\
           --streams N               concurrent bandwidth streams, default 1\n\
           --concurrency-steps LIST  sweep steps, default 1,8,32,128\n\
           --timeout SECONDS         per-operation timeout, default 30\n\
         \n\
         Reporting options:\n\
           --stats                   sample docker stats during bandwidth cases\n\
           --stats-interval SECONDS  default 0.5\n\
           --stats-containers LIST   default rove-local-main,rove-local-hop-*\n\
           --json-out PATH           write machine-readable results"
    );
}

fn parse_csv<T>(input: &str, parse: impl Fn(&str) -> anyhow::Result<T>) -> anyhow::Result<Vec<T>> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse)
        .collect()
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
struct MetricSummary {
    min: f64,
    p50: f64,
    p90: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

impl MetricSummary {
    fn from_sorted(sorted: &[f64]) -> Option<Self> {
        if sorted.is_empty() {
            return None;
        }
        Some(MetricSummary {
            min: sorted[0],
            p50: percentile(sorted, 0.50),
            p90: percentile(sorted, 0.90),
            p95: percentile(sorted, 0.95),
            p99: percentile(sorted, 0.99),
            max: sorted[sorted.len() - 1],
        })
    }
}

fn percentile(sorted: &[f64], ratio: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * ratio).ceil() as usize)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted[idx]
}

fn summarize(mut values: Vec<f64>) -> Option<MetricSummary> {
    values.sort_by(|a, b| a.partial_cmp(b).expect("latency values are finite"));
    MetricSummary::from_sorted(&values)
}

#[derive(Debug, Clone, Default)]
struct PhaseTimings {
    connect_ms: f64,
    tls_ms: Option<f64>,
    tunnel_ms: f64,
    request_ms: f64,
}

#[derive(Debug, Clone)]
struct LatencySample {
    ok: bool,
    total_ms: f64,
    phases: Option<PhaseTimings>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct LatencyReport {
    path: IngressPath,
    inbound: Inbound,
    mode: Mode,
    loop_kind: &'static str,
    requests: usize,
    concurrency: usize,
    rate: Option<f64>,
    ok: usize,
    failed: usize,
    elapsed_ms: f64,
    rps: f64,
    total_ms: Option<MetricSummary>,
    connect_ms: Option<MetricSummary>,
    tls_ms: Option<MetricSummary>,
    tunnel_ms: Option<MetricSummary>,
    request_ms: Option<MetricSummary>,
    errors: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct BandwidthReport {
    path: IngressPath,
    inbound: Inbound,
    mode: Mode,
    direction: Direction,
    streams: usize,
    payload_per_stream_mib: usize,
    ok: usize,
    failed: usize,
    elapsed_ms: f64,
    throughput_mib_s: f64,
    throughput_mbit_s: f64,
    first_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct SweepPoint {
    concurrency: usize,
    ok: usize,
    failed: usize,
    rps: f64,
    total_ms: Option<MetricSummary>,
}

#[derive(Debug, Serialize)]
struct SweepReport {
    path: IngressPath,
    inbound: Inbound,
    mode: Mode,
    requests_per_step: usize,
    points: Vec<SweepPoint>,
}

#[derive(Debug, Serialize)]
struct RateLimitReport {
    path: IngressPath,
    inbound: Inbound,
    direction: Direction,
    configured_rate_bytes_s: u64,
    payload_mib: usize,
    elapsed_ms: f64,
    measured_bytes_s: f64,
    /// Burst-adjusted expectation: the token bucket starts with one second of
    /// budget, so `payload / ((payload - rate) / rate)` is the honest target.
    expected_bytes_s: f64,
    error_percent: f64,
}

#[derive(Debug, Serialize)]
struct ConnectionLimitReport {
    path: IngressPath,
    inbound: Inbound,
    configured_max: usize,
    attempted: usize,
    admitted: usize,
    rejected: usize,
    rejected_as_expected: bool,
}

#[derive(Debug, Serialize)]
struct ContainerStats {
    container: String,
    samples: usize,
    cpu_avg: f64,
    cpu_p95: f64,
    cpu_max: f64,
    mem_max_mib: f64,
}

#[derive(Debug, Default, Serialize)]
struct Report {
    latency: Vec<LatencyReport>,
    bandwidth: Vec<BandwidthReport>,
    sweep: Vec<SweepReport>,
    rate_limit: Vec<RateLimitReport>,
    connection_limit: Vec<ConnectionLimitReport>,
    container_stats: Vec<ContainerStats>,
}

// ---------------------------------------------------------------------------
// Target HTTP server (payload source/sink shared by every case)
// ---------------------------------------------------------------------------

async fn start_target(bind: &str, port: u16, payload_bytes: usize) -> anyhow::Result<SocketAddr> {
    let addr = format!("{bind}:{port}");
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind target server {addr}"))?;
    let bound = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let _ = stream.set_nodelay(true);
                    tokio::spawn(handle_target(stream, payload_bytes));
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(bound)
}

async fn handle_target(mut stream: TcpStream, payload_bytes: usize) {
    let Ok((head, body)) = read_http_head_and_remainder(&mut stream).await else {
        return;
    };
    let request_line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    if request_line.starts_with(b"GET /download") {
        let bytes = parse_download_bytes(request_line).unwrap_or(payload_bytes);
        let response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {bytes}\r\nConnection: close\r\n\r\n");
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
        let mut remaining = bytes;
        while remaining > 0 {
            let n = cmp::min(remaining, CHUNK.len());
            if stream.write_all(&CHUNK[..n]).await.is_err() {
                return;
            }
            remaining -= n;
        }
        let _ = stream.flush().await;
    } else if request_line.starts_with(b"GET ") {
        let body = b"rove-local-benchmark\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.write_all(body).await;
        let _ = stream.flush().await;
    } else if request_line.starts_with(b"POST ") {
        let mut remaining = parse_content_length(&head).saturating_sub(body.len());
        let mut buf = vec![0u8; 256 * 1024];
        while remaining > 0 {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => remaining = remaining.saturating_sub(n),
            }
        }
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await;
    }
}

/// Parse `bytes=N` from a `GET /download?bytes=N HTTP/1.1` request line.
fn parse_download_bytes(request_line: &[u8]) -> Option<usize> {
    let line = std::str::from_utf8(request_line).ok()?;
    let path = line.split_whitespace().nth(1)?;
    let query = path.split_once('?')?.1;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix("bytes="))
        .and_then(|v| v.parse().ok())
}

async fn read_http_head_and_remainder(
    stream: &mut (impl IoStream + ?Sized),
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(pos) = find_head_end(&data) {
            let remainder = data.split_off(pos);
            return Ok((data, remainder));
        }
        anyhow::ensure!(data.len() <= 64 * 1024, "HTTP head too large");
        let n = stream.read(&mut buf).await?;
        anyhow::ensure!(n > 0, "connection closed before HTTP head");
        data.extend_from_slice(&buf[..n]);
    }
}

fn find_head_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

fn parse_content_length(head: &[u8]) -> usize {
    for line in head.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix(b"content-length:") {
            if let Ok(text) = std::str::from_utf8(rest) {
                if let Ok(value) = text.trim().parse() {
                    return value;
                }
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Tunnel client: inbound handshake (TCP / TLS / HTTP CONNECT / SOCKS5)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct TunnelClient {
    proxy_addr: String,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    path: IngressPath,
    inbound: Inbound,
    target_host: String,
    target_port: u16,
    timeout: Duration,
}

impl TunnelClient {
    fn new(args: &Args, path: IngressPath, inbound: Inbound) -> anyhow::Result<Self> {
        let tls = if inbound.tls() {
            let connector = tls_connector(args)?;
            let name = ServerName::try_from(args.tls_server_name.clone())
                .with_context(|| format!("bad --tls-server-name {}", args.tls_server_name))?;
            Some((connector, name))
        } else {
            None
        };
        Ok(TunnelClient {
            proxy_addr: format!("{}:{}", args.proxy_host, args.inbound_port(path, inbound)),
            tls,
            path,
            inbound,
            target_host: args.target_host.clone(),
            target_port: args.target_port,
            timeout: args.timeout,
        })
    }

    /// Establish an authenticated tunnel to the benchmark target, recording
    /// per-phase timings. On success the returned stream is the raw tunnel.
    async fn open(&self, mode: Mode) -> anyhow::Result<(Box<dyn IoStream>, PhaseTimings)> {
        let mut phases = PhaseTimings::default();

        let started = Instant::now();
        let tcp = tokio::time::timeout(self.timeout, TcpStream::connect(&self.proxy_addr))
            .await
            .context("tcp connect timeout")?
            .with_context(|| format!("tcp connect {}", self.proxy_addr))?;
        let _ = tcp.set_nodelay(true);
        phases.connect_ms = started.elapsed().as_secs_f64() * 1000.0;

        let mut stream: Box<dyn IoStream> = match &self.tls {
            Some((connector, name)) => {
                let tls_started = Instant::now();
                let tls = tokio::time::timeout(self.timeout, connector.connect(name.clone(), tcp))
                    .await
                    .context("tls handshake timeout")?
                    .context("tls handshake")?;
                phases.tls_ms = Some(tls_started.elapsed().as_secs_f64() * 1000.0);
                Box::new(tls)
            }
            None => Box::new(tcp),
        };

        let tunnel_started = Instant::now();
        match self.inbound {
            Inbound::Http | Inbound::HttpsTls => {
                tokio::time::timeout(self.timeout, self.http_connect(&mut stream, mode))
                    .await
                    .context("http connect timeout")??;
            }
            Inbound::Socks5 | Inbound::Socks5Tls => {
                tokio::time::timeout(self.timeout, self.socks5_connect(&mut stream, mode))
                    .await
                    .context("socks5 connect timeout")??;
            }
        }
        phases.tunnel_ms = tunnel_started.elapsed().as_secs_f64() * 1000.0;
        Ok((stream, phases))
    }

    async fn http_connect(&self, stream: &mut Box<dyn IoStream>, mode: Mode) -> anyhow::Result<()> {
        let target = format!("{}:{}", self.target_host, self.target_port);
        let token = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            mode.username(),
            PASSWORD
        ));
        let request = format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        let (head, remainder) = read_http_head_and_remainder(stream.as_mut()).await?;
        anyhow::ensure!(remainder.is_empty(), "unexpected bytes after CONNECT reply");
        let first = head.split(|b| *b == b'\n').next().unwrap_or_default();
        let first = String::from_utf8_lossy(first);
        anyhow::ensure!(
            first.starts_with("HTTP/1.1 200"),
            "CONNECT refused: {}",
            first.trim()
        );
        Ok(())
    }

    async fn socks5_connect(
        &self,
        stream: &mut Box<dyn IoStream>,
        mode: Mode,
    ) -> anyhow::Result<()> {
        // Method negotiation: Rove requires username/password (0x02).
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        anyhow::ensure!(
            reply == [0x05, 0x02],
            "socks5 method negotiation failed: {reply:02x?}"
        );

        // RFC 1929 username/password subnegotiation.
        let user = mode.username().as_bytes();
        let pass = PASSWORD.as_bytes();
        let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
        auth.push(0x01);
        auth.push(user.len() as u8);
        auth.extend_from_slice(user);
        auth.push(pass.len() as u8);
        auth.extend_from_slice(pass);
        stream.write_all(&auth).await?;
        stream.read_exact(&mut reply).await?;
        anyhow::ensure!(reply[1] == 0x00, "socks5 auth failed: {reply:02x?}");

        // CONNECT request, domain address form.
        let host = self.target_host.as_bytes();
        anyhow::ensure!(host.len() <= 255, "target host too long");
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&self.target_port.to_be_bytes());
        stream.write_all(&req).await?;

        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        anyhow::ensure!(
            head[1] == 0x00,
            "socks5 connect refused: rep={:#04x}",
            head[1]
        );
        match head[3] {
            0x01 => {
                let mut rest = [0u8; 6];
                stream.read_exact(&mut rest).await?;
            }
            0x04 => {
                let mut rest = [0u8; 18];
                stream.read_exact(&mut rest).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut rest = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut rest).await?;
            }
            other => anyhow::bail!("socks5 reply bad atyp {other:#04x}"),
        }
        Ok(())
    }
}

fn tls_connector(args: &Args) -> anyhow::Result<TlsConnector> {
    if args.insecure_tls {
        return Ok(rove::tls::insecure_client_connector());
    }
    let mut roots = rustls::RootCertStore::empty();
    let ca = args.ca_cert.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no CA certificate: run ./scripts/generate-local-certs.sh, pass --ca-cert, or use --insecure-tls"
        )
    })?;
    let pem = std::fs::read(ca).with_context(|| format!("read --ca-cert {}", ca.display()))?;
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
        roots
            .add(cert.context("parse CA certificate")?)
            .context("add CA certificate")?;
    }
    anyhow::ensure!(!roots.is_empty(), "no certificates in {}", ca.display());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

// ---------------------------------------------------------------------------
// Latency benchmark (closed-loop or open-loop)
// ---------------------------------------------------------------------------

async fn one_request(client: &TunnelClient, mode: Mode) -> LatencySample {
    let started = Instant::now();
    match one_request_inner(client, mode).await {
        Ok(phases) => LatencySample {
            ok: true,
            total_ms: started.elapsed().as_secs_f64() * 1000.0,
            phases: Some(phases),
            error: None,
        },
        Err(e) => LatencySample {
            ok: false,
            total_ms: started.elapsed().as_secs_f64() * 1000.0,
            phases: None,
            error: Some(root_error(&e)),
        },
    }
}

async fn one_request_inner(client: &TunnelClient, mode: Mode) -> anyhow::Result<PhaseTimings> {
    let (mut stream, mut phases) = client.open(mode).await?;
    let request_started = Instant::now();
    let target = format!("{}:{}", client.target_host, client.target_port);
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let response = tokio::time::timeout(client.timeout, read_to_end(&mut stream))
        .await
        .context("read response timeout")??;
    anyhow::ensure!(
        find_subslice(&response, b"rove-local-benchmark").is_some(),
        "unexpected target response"
    );
    phases.request_ms = request_started.elapsed().as_secs_f64() * 1000.0;
    Ok(phases)
}

async fn read_to_end(stream: &mut Box<dyn IoStream>) -> anyhow::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(data);
        }
        data.extend_from_slice(&buf[..n]);
        anyhow::ensure!(data.len() <= 1024 * 1024, "response too large");
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Reduce an error chain to its terse root cause for aggregation.
fn root_error(error: &anyhow::Error) -> String {
    error
        .chain()
        .next_back()
        .map(|e| e.to_string())
        .unwrap_or_else(|| error.to_string())
}

async fn run_warmup(client: &TunnelClient, mode: Mode, warmup: usize, concurrency: usize) {
    if warmup == 0 {
        return;
    }
    let sem = Arc::new(Semaphore::new(concurrency.min(warmup)));
    let mut tasks = Vec::with_capacity(warmup);
    for _ in 0..warmup {
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let _ = one_request(&client, mode).await;
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
}

async fn run_latency_case(
    args: &Args,
    client: &TunnelClient,
    mode: Mode,
    requests: usize,
    concurrency: usize,
) -> LatencyReport {
    run_warmup(client, mode, args.warmup, concurrency).await;

    let started = Instant::now();
    let samples = match args.rate {
        None => closed_loop(client, mode, requests, concurrency).await,
        Some(rate) => open_loop(client, mode, requests, rate).await,
    };
    let elapsed = started.elapsed().as_secs_f64();

    let ok: Vec<&LatencySample> = samples.iter().filter(|s| s.ok).collect();
    let failed = samples.len() - ok.len();
    let mut errors: BTreeMap<String, usize> = BTreeMap::new();
    for sample in &samples {
        if let Some(error) = &sample.error {
            *errors.entry(error.clone()).or_default() += 1;
        }
    }

    let phase = |f: fn(&PhaseTimings) -> Option<f64>| -> Option<MetricSummary> {
        summarize(
            ok.iter()
                .filter_map(|s| s.phases.as_ref().and_then(f))
                .collect(),
        )
    };

    LatencyReport {
        path: client.path,
        inbound: client.inbound,
        mode,
        loop_kind: if args.rate.is_some() {
            "open"
        } else {
            "closed"
        },
        requests,
        concurrency,
        rate: args.rate,
        ok: ok.len(),
        failed,
        elapsed_ms: elapsed * 1000.0,
        rps: if elapsed > 0.0 {
            ok.len() as f64 / elapsed
        } else {
            0.0
        },
        total_ms: summarize(ok.iter().map(|s| s.total_ms).collect()),
        connect_ms: phase(|p| Some(p.connect_ms)),
        tls_ms: phase(|p| p.tls_ms),
        tunnel_ms: phase(|p| Some(p.tunnel_ms)),
        request_ms: phase(|p| Some(p.request_ms)),
        errors,
    }
}

async fn closed_loop(
    client: &TunnelClient,
    mode: Mode,
    requests: usize,
    concurrency: usize,
) -> Vec<LatencySample> {
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::with_capacity(requests);
    for _ in 0..requests {
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            one_request(&client, mode).await
        }));
    }
    collect_samples(tasks).await
}

/// Open-loop load: requests start on a fixed schedule regardless of how slow
/// earlier ones are, so recorded latency includes queueing (no coordinated
/// omission).
async fn open_loop(
    client: &TunnelClient,
    mode: Mode,
    requests: usize,
    rate: f64,
) -> Vec<LatencySample> {
    let interval = Duration::from_secs_f64(1.0 / rate);
    let base = Instant::now();
    let mut tasks = Vec::with_capacity(requests);
    for n in 0..requests {
        let scheduled = base + interval.mul_f64(n as f64);
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            tokio::time::sleep_until(scheduled.into()).await;
            one_request(&client, mode).await
        }));
    }
    collect_samples(tasks).await
}

async fn collect_samples(tasks: Vec<tokio::task::JoinHandle<LatencySample>>) -> Vec<LatencySample> {
    let mut samples = Vec::with_capacity(tasks.len());
    for task in tasks {
        samples.push(task.await.unwrap_or_else(|e| LatencySample {
            ok: false,
            total_ms: 0.0,
            phases: None,
            error: Some(format!("worker panicked: {e}")),
        }));
    }
    samples
}

fn print_latency(report: &LatencyReport) {
    println!(
        "\nlatency path={} inbound={} mode={} loop={}",
        report.path.as_str(),
        report.inbound.as_str(),
        report.mode.as_str(),
        report.loop_kind
    );
    println!(
        "  requests={} concurrency={}{} elapsed={:.3}s ok={} failed={} rps={:.1}",
        report.requests,
        report.concurrency,
        report
            .rate
            .map(|r| format!(" rate={r:.1}/s"))
            .unwrap_or_default(),
        report.elapsed_ms / 1000.0,
        report.ok,
        report.failed,
        report.rps
    );
    let show = |name: &str, m: &Option<MetricSummary>| {
        if let Some(m) = m {
            println!(
                "  {name} min={:.2} p50={:.2} p90={:.2} p95={:.2} p99={:.2} max={:.2}",
                m.min, m.p50, m.p90, m.p95, m.p99, m.max
            );
        }
    };
    show("total_ms  ", &report.total_ms);
    show("connect_ms", &report.connect_ms);
    show("tls_ms    ", &report.tls_ms);
    show("tunnel_ms ", &report.tunnel_ms);
    show("request_ms", &report.request_ms);
    for (error, count) in &report.errors {
        println!("  error x{count}: {error}");
    }
}

// ---------------------------------------------------------------------------
// Bandwidth benchmark
// ---------------------------------------------------------------------------

async fn transfer_once(
    client: &TunnelClient,
    mode: Mode,
    direction: Direction,
    payload_bytes: usize,
) -> anyhow::Result<usize> {
    let (mut stream, _) = client.open(mode).await?;
    let target = format!("{}:{}", client.target_host, client.target_port);
    match direction {
        Direction::Download => {
            stream
                .write_all(
                    format!(
                        "GET /download?bytes={payload_bytes} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            let (head, body) = read_http_head_and_remainder(stream.as_mut()).await?;
            let expected = parse_content_length(&head);
            anyhow::ensure!(
                expected == payload_bytes,
                "target advertised {expected} bytes, expected {payload_bytes}"
            );
            let mut received = body.len();
            let mut buf = vec![0u8; 256 * 1024];
            while received < expected {
                let n = stream.read(&mut buf).await?;
                anyhow::ensure!(n > 0, "connection closed at {received}/{expected} bytes");
                received += n;
            }
            Ok(received)
        }
        Direction::Upload => {
            stream
                .write_all(
                    format!(
                        "POST /upload HTTP/1.1\r\nHost: {target}\r\nContent-Length: {payload_bytes}\r\nConnection: close\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            let mut remaining = payload_bytes;
            while remaining > 0 {
                let n = cmp::min(remaining, CHUNK.len());
                stream.write_all(&CHUNK[..n]).await?;
                remaining -= n;
            }
            stream.flush().await?;
            let (head, _) = read_http_head_and_remainder(stream.as_mut()).await?;
            let first = head.split(|b| *b == b'\n').next().unwrap_or_default();
            let first = String::from_utf8_lossy(first);
            anyhow::ensure!(
                first.starts_with("HTTP/1.1 200"),
                "upload refused: {}",
                first.trim()
            );
            Ok(payload_bytes)
        }
    }
}

async fn run_bandwidth_case(
    args: &Args,
    client: &TunnelClient,
    mode: Mode,
    direction: Direction,
) -> BandwidthReport {
    let payload_bytes = args.mib * 1024 * 1024;
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(args.streams);
    for _ in 0..args.streams {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            tokio::time::timeout(
                client.timeout,
                transfer_once(&client, mode, direction, payload_bytes),
            )
            .await
            .map_err(|_| anyhow::anyhow!("transfer timeout"))
            .and_then(|r| r)
        }));
    }

    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut total_bytes = 0usize;
    let mut first_error = None;
    for task in tasks {
        match task.await {
            Ok(Ok(bytes)) => {
                ok += 1;
                total_bytes += bytes;
            }
            Ok(Err(e)) => {
                failed += 1;
                first_error.get_or_insert_with(|| root_error(&e));
            }
            Err(e) => {
                failed += 1;
                first_error.get_or_insert_with(|| format!("worker panicked: {e}"));
            }
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    let mib = total_bytes as f64 / 1024.0 / 1024.0;

    BandwidthReport {
        path: client.path,
        inbound: client.inbound,
        mode,
        direction,
        streams: args.streams,
        payload_per_stream_mib: args.mib,
        ok,
        failed,
        elapsed_ms: elapsed * 1000.0,
        throughput_mib_s: if elapsed > 0.0 { mib / elapsed } else { 0.0 },
        throughput_mbit_s: if elapsed > 0.0 {
            total_bytes as f64 * 8.0 / elapsed / 1_000_000.0
        } else {
            0.0
        },
        first_error,
    }
}

fn print_bandwidth(report: &BandwidthReport) {
    println!(
        "\nbandwidth path={} inbound={} mode={} direction={}",
        report.path.as_str(),
        report.inbound.as_str(),
        report.mode.as_str(),
        report.direction.as_str()
    );
    println!(
        "  streams={} payload_per_stream={}MiB elapsed={:.3}s ok={} failed={}",
        report.streams,
        report.payload_per_stream_mib,
        report.elapsed_ms / 1000.0,
        report.ok,
        report.failed
    );
    println!(
        "  throughput={:.1}MiB/s {:.1}Mbit/s",
        report.throughput_mib_s, report.throughput_mbit_s
    );
    if let Some(error) = &report.first_error {
        println!("  first_error={error}");
    }
}

// ---------------------------------------------------------------------------
// Concurrency sweep
// ---------------------------------------------------------------------------

async fn run_sweep(args: &Args, client: &TunnelClient, mode: Mode) -> SweepReport {
    let mut points = Vec::with_capacity(args.concurrency_steps.len());
    for &concurrency in &args.concurrency_steps {
        let requests = args.requests.min(cmp::max(concurrency * 25, 200));
        let report = run_latency_case(args, client, mode, requests, concurrency).await;
        println!(
            "sweep path={} inbound={} mode={} concurrency={} ok={} failed={} rps={:.1} p50={:.2} p99={:.2}",
            client.path.as_str(),
            client.inbound.as_str(),
            mode.as_str(),
            concurrency,
            report.ok,
            report.failed,
            report.rps,
            report.total_ms.as_ref().map_or(0.0, |m| m.p50),
            report.total_ms.as_ref().map_or(0.0, |m| m.p99),
        );
        points.push(SweepPoint {
            concurrency,
            ok: report.ok,
            failed: report.failed,
            rps: report.rps,
            total_ms: report.total_ms,
        });
    }
    SweepReport {
        path: client.path,
        inbound: client.inbound,
        mode,
        requests_per_step: args.requests,
        points,
    }
}

// ---------------------------------------------------------------------------
// Limits: rate-limit accuracy + max_connections probe
// ---------------------------------------------------------------------------

/// `bench-limited` in docker/local/snapshot.json: 1MiB/s both ways, 2 conns.
const LIMITED_RATE_BYTES_S: u64 = 1_048_576;
const LIMITED_MAX_CONNECTIONS: usize = 2;
const LIMITED_PAYLOAD_MIB: usize = 8;

async fn run_rate_limit_case(
    args: &Args,
    client: &TunnelClient,
    direction: Direction,
) -> anyhow::Result<RateLimitReport> {
    let payload_bytes = LIMITED_PAYLOAD_MIB * 1024 * 1024;
    let rate = LIMITED_RATE_BYTES_S as f64;
    let started = Instant::now();
    let timeout =
        Duration::from_secs_f64((payload_bytes as f64 / rate) * 3.0 + args.timeout.as_secs_f64());
    let bytes = tokio::time::timeout(
        timeout,
        transfer_once(client, Mode::Limited, direction, payload_bytes),
    )
    .await
    .map_err(|_| anyhow::anyhow!("rate-limited transfer timed out"))??;
    let elapsed = started.elapsed().as_secs_f64();
    let measured = bytes as f64 / elapsed;
    // The token bucket starts full with one second of rate, so the first
    // `rate` bytes are an expected burst; model it instead of flagging it.
    let expected_elapsed = (payload_bytes as f64 - rate).max(0.0) / rate;
    let expected = if expected_elapsed > 0.0 {
        bytes as f64 / expected_elapsed
    } else {
        rate
    };
    let error_percent = (measured - expected) / expected * 100.0;

    Ok(RateLimitReport {
        path: client.path,
        inbound: client.inbound,
        direction,
        configured_rate_bytes_s: LIMITED_RATE_BYTES_S,
        payload_mib: LIMITED_PAYLOAD_MIB,
        elapsed_ms: elapsed * 1000.0,
        measured_bytes_s: measured,
        expected_bytes_s: expected,
        error_percent,
    })
}

/// Hold `max + 2` tunnels open concurrently through the limited user and
/// count how many the proxy admits: exactly `max` should survive.
async fn run_connection_limit_case(
    _args: &Args,
    client: &TunnelClient,
) -> anyhow::Result<ConnectionLimitReport> {
    let attempted = LIMITED_MAX_CONNECTIONS + 2;
    let hold = Duration::from_millis(1500);
    let mut tasks = Vec::with_capacity(attempted);
    for n in 0..attempted {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            // Slight stagger so admission order is deterministic-ish.
            tokio::time::sleep(Duration::from_millis(50 * n as u64)).await;
            match client.open(Mode::Limited).await {
                Ok((mut stream, _)) => {
                    // Keep the tunnel open so it counts as active.
                    tokio::time::sleep(hold).await;
                    let _ = stream.shutdown().await;
                    true
                }
                Err(_) => false,
            }
        }));
    }
    let mut admitted = 0usize;
    for task in tasks {
        if task.await.unwrap_or(false) {
            admitted += 1;
        }
    }
    let rejected = attempted - admitted;
    Ok(ConnectionLimitReport {
        path: client.path,
        inbound: client.inbound,
        configured_max: LIMITED_MAX_CONNECTIONS,
        attempted,
        admitted,
        rejected,
        rejected_as_expected: admitted == LIMITED_MAX_CONNECTIONS,
    })
}

fn print_rate_limit(report: &RateLimitReport) {
    println!(
        "\nrate_limit path={} inbound={} direction={} configured={}B/s",
        report.path.as_str(),
        report.inbound.as_str(),
        report.direction.as_str(),
        report.configured_rate_bytes_s
    );
    println!(
        "  payload={}MiB elapsed={:.3}s measured={:.0}B/s expected={:.0}B/s error={:+.1}%",
        report.payload_mib,
        report.elapsed_ms / 1000.0,
        report.measured_bytes_s,
        report.expected_bytes_s,
        report.error_percent
    );
}

fn print_connection_limit(report: &ConnectionLimitReport) {
    println!(
        "\nconnection_limit path={} inbound={} configured_max={} attempted={} admitted={} rejected={} ok={}",
        report.path.as_str(),
        report.inbound.as_str(),
        report.configured_max,
        report.attempted,
        report.admitted,
        report.rejected,
        report.rejected_as_expected
    );
}

// ---------------------------------------------------------------------------
// docker stats sampling (optional, bandwidth phase only)
// ---------------------------------------------------------------------------

struct StatsSampler {
    handle: tokio::task::JoinHandle<Vec<(String, f64, f64)>>,
    stop: Arc<tokio::sync::Notify>,
}

impl StatsSampler {
    fn start(containers: Vec<String>, interval: Duration) -> Self {
        let stop = Arc::new(tokio::sync::Notify::new());
        let stop_signal = stop.clone();
        let handle = tokio::spawn(async move {
            let mut samples: Vec<(String, f64, f64)> = Vec::new();
            loop {
                tokio::select! {
                    _ = stop_signal.notified() => break,
                    _ = tokio::time::sleep(interval) => {
                        if let Ok(batch) = sample_docker_stats(&containers).await {
                            samples.extend(batch);
                        }
                    }
                }
            }
            samples
        });
        StatsSampler { handle, stop }
    }

    async fn finish(self) -> Vec<ContainerStats> {
        self.stop.notify_one();
        let samples = self.handle.await.unwrap_or_default();
        let mut grouped: BTreeMap<String, (Vec<f64>, Vec<f64>)> = BTreeMap::new();
        for (name, cpu, mem) in samples {
            let entry = grouped.entry(name).or_default();
            entry.0.push(cpu);
            entry.1.push(mem);
        }
        grouped
            .into_iter()
            .map(|(container, (mut cpu, mem))| {
                cpu.sort_by(|a, b| a.partial_cmp(b).expect("cpu values are finite"));
                ContainerStats {
                    container,
                    samples: cpu.len(),
                    cpu_avg: cpu.iter().sum::<f64>() / cpu.len().max(1) as f64,
                    cpu_p95: percentile(&cpu, 0.95),
                    cpu_max: cpu.last().copied().unwrap_or(0.0),
                    mem_max_mib: mem.into_iter().fold(0.0, f64::max),
                }
            })
            .collect()
    }
}

async fn sample_docker_stats(containers: &[String]) -> anyhow::Result<Vec<(String, f64, f64)>> {
    // tokio's `process` feature is not enabled in this crate; a blocking
    // subprocess on the blocking pool keeps the sampler off the runtime.
    let names = containers.to_vec();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("docker")
            .arg("stats")
            .arg("--no-stream")
            .arg("--format")
            .arg("{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}")
            .args(&names)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
    })
    .await
    .context("join docker stats task")?
    .context("run docker stats")?;
    anyhow::ensure!(output.status.success(), "docker stats failed");
    let text = String::from_utf8_lossy(&output.stdout);
    let mut samples = Vec::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        let (Some(name), Some(cpu), Some(mem)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let cpu = cpu.trim().trim_end_matches('%').parse().unwrap_or(0.0);
        let mem = parse_mem_mib(mem.split('/').next().unwrap_or_default().trim());
        samples.push((name.to_string(), cpu, mem));
    }
    Ok(samples)
}

fn parse_mem_mib(value: &str) -> f64 {
    let split = value
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(value.len());
    let amount: f64 = value[..split].trim().parse().unwrap_or(0.0);
    match value[split..].trim() {
        "B" => amount / 1024.0 / 1024.0,
        "KB" | "KiB" => amount / 1024.0,
        "MB" | "MiB" => amount,
        "GB" | "GiB" => amount * 1024.0,
        "TB" | "TiB" => amount * 1024.0 * 1024.0,
        _ => 0.0,
    }
}

fn print_container_stats(stats: &[ContainerStats]) {
    if stats.is_empty() {
        return;
    }
    println!("\ncontainer_resource_stats");
    for s in stats {
        println!(
            "  {}: samples={} cpu_avg={:.1}% cpu_p95={:.1}% cpu_max={:.1}% mem_max={:.1}MiB",
            s.container, s.samples, s.cpu_avg, s.cpu_p95, s.cpu_max, s.mem_max_mib
        );
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rove::tls::init_crypto();
    let args = Args::parse()?;

    let payload_bytes = args.mib * 1024 * 1024;
    start_target(&args.target_bind, args.target_port, payload_bytes).await?;

    let mut report = Report::default();

    if matches!(args.command, Command::Latency | Command::All) {
        for &path in &args.paths {
            for &inbound in &args.inbounds {
                let client = TunnelClient::new(&args, path, inbound)?;
                for &mode in &args.modes {
                    let case =
                        run_latency_case(&args, &client, mode, args.requests, args.concurrency)
                            .await;
                    print_latency(&case);
                    report.latency.push(case);
                }
            }
        }
    }

    if matches!(args.command, Command::Bandwidth | Command::All) {
        let sampler = args
            .stats
            .then(|| StatsSampler::start(args.stats_containers.clone(), args.stats_interval));
        for &path in &args.paths {
            for &inbound in &args.inbounds {
                let client = TunnelClient::new(&args, path, inbound)?;
                for &mode in &args.modes {
                    for &direction in &args.directions {
                        let case = run_bandwidth_case(&args, &client, mode, direction).await;
                        print_bandwidth(&case);
                        report.bandwidth.push(case);
                    }
                }
            }
        }
        if let Some(sampler) = sampler {
            report.container_stats = sampler.finish().await;
            print_container_stats(&report.container_stats);
        }
    }

    if matches!(args.command, Command::Sweep | Command::All) {
        // Sweep drives the plain HTTP inbound unless the user narrowed
        // --inbounds; one inbound x the first mode per selected ingress path is
        // enough to expose scaling without exploding the matrix.
        let inbound = if args.inbounds.contains(&Inbound::Http) {
            Inbound::Http
        } else {
            args.inbounds[0]
        };
        let mode = args.modes[0];
        for &path in &args.paths {
            let client = TunnelClient::new(&args, path, inbound)?;
            let sweep = run_sweep(&args, &client, mode).await;
            report.sweep.push(sweep);
        }
    }

    if matches!(args.command, Command::Limits | Command::All) {
        let inbound = if args.inbounds.contains(&Inbound::Http) {
            Inbound::Http
        } else {
            args.inbounds[0]
        };
        for &path in &args.paths {
            let client = TunnelClient::new(&args, path, inbound)?;
            for &direction in &args.directions {
                match run_rate_limit_case(&args, &client, direction).await {
                    Ok(case) => {
                        print_rate_limit(&case);
                        report.rate_limit.push(case);
                    }
                    Err(e) => println!(
                        "\nrate_limit path={} inbound={} direction={} failed: {e:#}",
                        path.as_str(),
                        inbound.as_str(),
                        direction.as_str()
                    ),
                }
            }
            match run_connection_limit_case(&args, &client).await {
                Ok(case) => {
                    print_connection_limit(&case);
                    report.connection_limit.push(case);
                }
                Err(e) => println!(
                    "\nconnection_limit path={} inbound={} failed: {e:#}",
                    path.as_str(),
                    inbound.as_str()
                ),
            }
        }
    }

    if let Some(path) = &args.json_out {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
        println!("\njson_out={}", path.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_path_parser_is_explicit_and_backward_compatible() {
        assert_eq!(IngressPath::parse("local").unwrap(), IngressPath::Local);
        assert_eq!(
            IngressPath::parse("reverse-ingress").unwrap(),
            IngressPath::ReverseIngress
        );
        assert_eq!(
            IngressPath::parse("ingress").unwrap(),
            IngressPath::ReverseIngress
        );
        assert!(IngressPath::parse("reverse").is_err());
    }
}
