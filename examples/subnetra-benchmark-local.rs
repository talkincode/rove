use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine as _;
use rove::engine::Engine;
use rove::model::{
    Decision, RawRoutingPolicy, RawSnapshotV4, RawUserV4, Snapshot, Upstream, UpstreamKind,
    V4_SCHEMA_VERSION,
};
use rove::subnetra::config::{PeerConfig, SubnetraConfig};
use rove::subnetra::{netstack, reactor, service};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

const USERNAME: &str = "bench-subnetra";
const PASSWORD: &str = "bench";
const HUB_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SPOKE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const HUB_PROXY_PORT: u16 = 8080;
const EGRESS_TARGET_PORT: u16 = 7000;
const EPOCH: u64 = 1_704_067_200_000_000_000;
const CHUNK: &[u8] = &[b'x'; 256 * 1024];
const IO_BUF_SIZE: usize = 256 * 1024;

type BenchStream = Box<dyn rove::io::IoStream>;

#[derive(Debug, Clone)]
struct Args {
    scenarios: Vec<Scenario>,
    requests: usize,
    concurrency: usize,
    warmup: usize,
    mib: usize,
    streams: usize,
    timeout: Duration,
    directions: Vec<Direction>,
    mtu: usize,
    json_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Scenario {
    SpokeEgress,
    HubInbound,
}

impl Scenario {
    fn as_str(self) -> &'static str {
        match self {
            Scenario::SpokeEgress => "spoke-egress",
            Scenario::HubInbound => "hub-inbound",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
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
}

#[derive(Debug, Clone, Serialize)]
struct LatencySample {
    ok: bool,
    total_ms: f64,
    overlay_connect_ms: Option<f64>,
    proxy_connect_ms: Option<f64>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct TransferSample {
    ok: bool,
    bytes_count: usize,
    elapsed_ms: f64,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScenarioReport {
    scenario: Scenario,
    mtu: usize,
    latency: LatencyReport,
    bandwidth: Vec<BandwidthReport>,
}

#[derive(Debug, Serialize)]
struct LatencyReport {
    requests: usize,
    concurrency: usize,
    ok: usize,
    failed: usize,
    rps: f64,
    total_ms: Option<MetricSummary>,
    overlay_connect_ms: Option<MetricSummary>,
    proxy_connect_ms: Option<MetricSummary>,
    first_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BandwidthReport {
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
struct MetricSummary {
    min: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    rove::tls::init_crypto();
    let args = Args::parse()?;
    let mut reports = Vec::new();

    for scenario in ordered_scenarios(&args.scenarios) {
        let report = match scenario {
            Scenario::SpokeEgress => run_spoke_egress(&args).await?,
            Scenario::HubInbound => run_hub_inbound(&args).await?,
        };
        print_report(&report);
        reports.push(report);
    }

    if let Some(path) = &args.json_out {
        let json = serde_json::to_string_pretty(&reports)?;
        std::fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
        println!("\njson_out={}", path.display());
    }

    Ok(())
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let mut parsed = Args {
            scenarios: vec![Scenario::SpokeEgress, Scenario::HubInbound],
            requests: 200,
            concurrency: 20,
            warmup: 20,
            mib: 64,
            streams: 1,
            timeout: Duration::from_secs(30),
            directions: vec![Direction::Download, Direction::Upload],
            mtu: rove::subnetra::INNER_MTU,
            json_out: None,
        };

        let argv = std::env::args().skip(1).collect::<Vec<_>>();
        let mut i = 0;
        while i < argv.len() {
            let key = argv[i].as_str();
            let value = |i: &mut usize| -> anyhow::Result<String> {
                *i += 1;
                argv.get(*i)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("{key} requires a value"))
            };

            match key {
                "--scenarios" => {
                    parsed.scenarios = parse_csv(&value(&mut i)?, parse_scenario)?;
                }
                "--requests" => parsed.requests = value(&mut i)?.parse()?,
                "--concurrency" => parsed.concurrency = value(&mut i)?.parse()?,
                "--warmup" => parsed.warmup = value(&mut i)?.parse()?,
                "--mib" => parsed.mib = value(&mut i)?.parse()?,
                "--streams" => parsed.streams = value(&mut i)?.parse()?,
                "--timeout" => {
                    let secs: f64 = value(&mut i)?.parse()?;
                    parsed.timeout = Duration::from_secs_f64(secs);
                }
                "--directions" => {
                    parsed.directions = parse_csv(&value(&mut i)?, parse_direction)?;
                }
                "--mtu" => parsed.mtu = value(&mut i)?.parse()?,
                "--json-out" => parsed.json_out = Some(PathBuf::from(value(&mut i)?)),
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument {other:?}; pass --help for usage"),
            }
            i += 1;
        }

        anyhow::ensure!(!parsed.scenarios.is_empty(), "--scenarios cannot be empty");
        anyhow::ensure!(
            !parsed.directions.is_empty(),
            "--directions cannot be empty"
        );
        anyhow::ensure!(parsed.concurrency > 0, "--concurrency must be > 0");
        anyhow::ensure!(parsed.streams > 0, "--streams must be > 0");
        anyhow::ensure!(parsed.requests > 0, "--requests must be > 0");
        anyhow::ensure!(
            (rove::subnetra::MIN_INNER_MTU..=rove::subnetra::INNER_MTU).contains(&parsed.mtu),
            "--mtu must be within [{}, {}]",
            rove::subnetra::MIN_INNER_MTU,
            rove::subnetra::INNER_MTU
        );
        Ok(parsed)
    }
}

fn print_usage() {
    println!(
        "Usage: cargo run --release --example subnetra-benchmark-local -- [options]\n\
         Options:\n\
           --scenarios LIST     spoke-egress,hub-inbound by default\n\
           --requests N         latency requests, default 200\n\
           --concurrency N      latency concurrency, default 20\n\
           --warmup N           unreported warmup requests per scenario, default 20\n\
           --mib N              MiB per bandwidth stream, default 64\n\
           --streams N          concurrent bandwidth streams, default 1\n\
           --directions LIST    download,upload by default\n\
           --timeout SECONDS    per operation timeout, default 30\n\
           --mtu N              Subnetra inner overlay MTU (576-1452), default 1452\n\
           --json-out PATH      write machine-readable results"
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

fn parse_scenario(input: &str) -> anyhow::Result<Scenario> {
    match input {
        "spoke-egress" => Ok(Scenario::SpokeEgress),
        "hub-inbound" => Ok(Scenario::HubInbound),
        other => anyhow::bail!("unknown scenario {other:?}; expected spoke-egress or hub-inbound"),
    }
}

fn parse_direction(input: &str) -> anyhow::Result<Direction> {
    match input {
        "download" => Ok(Direction::Download),
        "upload" => Ok(Direction::Upload),
        other => anyhow::bail!("unknown direction {other:?}; expected download or upload"),
    }
}

fn ordered_scenarios(input: &[Scenario]) -> Vec<Scenario> {
    let mut out = Vec::new();
    if input.contains(&Scenario::SpokeEgress) {
        out.push(Scenario::SpokeEgress);
    }
    if input.contains(&Scenario::HubInbound) {
        out.push(Scenario::HubInbound);
    }
    out
}

async fn run_spoke_egress(args: &Args) -> anyhow::Result<ScenarioReport> {
    let target =
        start_overlay_http_target(EGRESS_TARGET_PORT, args.mib * 1024 * 1024, args.mtu).await?;
    let spoke = start_spoke_service(target.udp, args.mtu).await?;
    let egress = Arc::new(rove::outbound::EgressContext::new(None, Some(spoke)));

    warmup(args, Scenario::SpokeEgress, egress.clone()).await;
    let latency = run_latency(args, Scenario::SpokeEgress, egress.clone()).await;
    let bandwidth = run_bandwidth(args, Scenario::SpokeEgress, egress).await;
    Ok(ScenarioReport {
        scenario: Scenario::SpokeEgress,
        mtu: args.mtu,
        latency,
        bandwidth,
    })
}

async fn run_hub_inbound(args: &Args) -> anyhow::Result<ScenarioReport> {
    let target = start_direct_http_target(args.mib * 1024 * 1024).await?;
    let (_hub, hub_udp) = start_hub_service(args.mtu).await?;
    let spoke = start_spoke_net(hub_udp, args.mtu).await?;

    warmup_hub_inbound(args, &spoke, target.addr).await;
    let latency = run_hub_inbound_latency(args, &spoke, target.addr).await;
    let bandwidth = run_hub_inbound_bandwidth(args, &spoke, target.addr).await;
    Ok(ScenarioReport {
        scenario: Scenario::HubInbound,
        mtu: args.mtu,
        latency,
        bandwidth,
    })
}

async fn warmup(args: &Args, scenario: Scenario, egress: Arc<rove::outbound::EgressContext>) {
    if args.warmup == 0 {
        return;
    }
    let small = Args {
        requests: args.warmup,
        concurrency: args.concurrency.min(args.warmup.max(1)),
        directions: Vec::new(),
        ..args.clone()
    };
    let _ = run_latency(&small, scenario, egress).await;
}

async fn warmup_hub_inbound(args: &Args, spoke: &netstack::NetHandle, target: SocketAddr) {
    if args.warmup == 0 {
        return;
    }
    let small = Args {
        requests: args.warmup,
        concurrency: args.concurrency.min(args.warmup.max(1)),
        directions: Vec::new(),
        ..args.clone()
    };
    let _ = run_hub_inbound_latency(&small, spoke, target).await;
}

async fn run_latency(
    args: &Args,
    scenario: Scenario,
    egress: Arc<rove::outbound::EgressContext>,
) -> LatencyReport {
    let sem = Arc::new(Semaphore::new(args.concurrency));
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(args.requests);
    for _ in 0..args.requests {
        let sem = sem.clone();
        let egress = egress.clone();
        let timeout = args.timeout;
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore open");
            match scenario {
                Scenario::SpokeEgress => spoke_egress_ping(timeout, &egress).await,
                Scenario::HubInbound => LatencySample {
                    ok: false,
                    total_ms: 0.0,
                    overlay_connect_ms: None,
                    proxy_connect_ms: None,
                    error: Some("hub-inbound requires a spoke handle".to_string()),
                },
            }
        }));
    }

    let mut samples = Vec::with_capacity(args.requests);
    for task in tasks {
        samples.push(task.await.unwrap_or_else(|e| LatencySample {
            ok: false,
            total_ms: 0.0,
            overlay_connect_ms: None,
            proxy_connect_ms: None,
            error: Some(format!("task join: {e}")),
        }));
    }
    summarize_latency(args.requests, args.concurrency, started.elapsed(), samples)
}

async fn run_hub_inbound_latency(
    args: &Args,
    spoke: &netstack::NetHandle,
    target: SocketAddr,
) -> LatencyReport {
    let sem = Arc::new(Semaphore::new(args.concurrency));
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(args.requests);
    for _ in 0..args.requests {
        let sem = sem.clone();
        let spoke = spoke.clone();
        let timeout = args.timeout;
        tasks.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore open");
            hub_inbound_ping(&spoke, target, timeout).await
        }));
    }

    let mut samples = Vec::with_capacity(args.requests);
    for task in tasks {
        samples.push(task.await.unwrap_or_else(|e| LatencySample {
            ok: false,
            total_ms: 0.0,
            overlay_connect_ms: None,
            proxy_connect_ms: None,
            error: Some(format!("task join: {e}")),
        }));
    }
    summarize_latency(args.requests, args.concurrency, started.elapsed(), samples)
}

async fn run_bandwidth(
    args: &Args,
    scenario: Scenario,
    egress: Arc<rove::outbound::EgressContext>,
) -> Vec<BandwidthReport> {
    let mut reports = Vec::new();
    for direction in &args.directions {
        let report = match scenario {
            Scenario::SpokeEgress => {
                run_spoke_egress_transfer(args, *direction, egress.clone()).await
            }
            Scenario::HubInbound => BandwidthReport {
                direction: *direction,
                streams: args.streams,
                payload_per_stream_mib: args.mib,
                ok: 0,
                failed: args.streams,
                elapsed_ms: 0.0,
                throughput_mib_s: 0.0,
                throughput_mbit_s: 0.0,
                first_error: Some("hub-inbound requires a spoke handle".to_string()),
            },
        };
        reports.push(report);
    }
    reports
}

async fn run_hub_inbound_bandwidth(
    args: &Args,
    spoke: &netstack::NetHandle,
    target: SocketAddr,
) -> Vec<BandwidthReport> {
    let mut reports = Vec::new();
    for direction in &args.directions {
        reports.push(run_hub_inbound_transfer(args, spoke, target, *direction).await);
    }
    reports
}

async fn spoke_egress_ping(
    timeout: Duration,
    egress: &rove::outbound::EgressContext,
) -> LatencySample {
    let started = Instant::now();
    let connect_started = Instant::now();
    let stream = match tokio::time::timeout(timeout, open_spoke_egress_stream(egress)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return failed_latency(started, Some(connect_started.elapsed()), None, e),
        Err(_) => {
            return failed_latency(
                started,
                Some(connect_started.elapsed()),
                None,
                anyhow::anyhow!("connect timed out"),
            )
        }
    };
    let connect_ms = connect_started.elapsed();
    match request_ping(stream, timeout).await {
        Ok(()) => LatencySample {
            ok: true,
            total_ms: elapsed_ms(started.elapsed()),
            overlay_connect_ms: Some(elapsed_ms(connect_ms)),
            proxy_connect_ms: None,
            error: None,
        },
        Err(e) => failed_latency(started, Some(connect_ms), None, e),
    }
}

async fn hub_inbound_ping(
    spoke: &netstack::NetHandle,
    target: SocketAddr,
    timeout: Duration,
) -> LatencySample {
    let started = Instant::now();
    let connect_started = Instant::now();
    let stream = match tokio::time::timeout(timeout, spoke.connect(HUB_IP, HUB_PROXY_PORT)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return failed_latency(
                started,
                Some(connect_started.elapsed()),
                None,
                anyhow::anyhow!(e),
            )
        }
        Err(_) => {
            return failed_latency(
                started,
                Some(connect_started.elapsed()),
                None,
                anyhow::anyhow!("overlay connect timed out"),
            )
        }
    };
    let overlay_ms = connect_started.elapsed();
    let proxy_started = Instant::now();
    let stream: BenchStream = Box::new(stream);
    let stream = match http_connect_over_stream(stream, target, timeout).await {
        Ok(s) => s,
        Err(e) => {
            return failed_latency(started, Some(overlay_ms), Some(proxy_started.elapsed()), e)
        }
    };
    let proxy_ms = proxy_started.elapsed();
    match request_ping(stream, timeout).await {
        Ok(()) => LatencySample {
            ok: true,
            total_ms: elapsed_ms(started.elapsed()),
            overlay_connect_ms: Some(elapsed_ms(overlay_ms)),
            proxy_connect_ms: Some(elapsed_ms(proxy_ms)),
            error: None,
        },
        Err(e) => failed_latency(started, Some(overlay_ms), Some(proxy_ms), e),
    }
}

fn failed_latency(
    started: Instant,
    overlay_connect: Option<Duration>,
    proxy_connect: Option<Duration>,
    error: anyhow::Error,
) -> LatencySample {
    LatencySample {
        ok: false,
        total_ms: elapsed_ms(started.elapsed()),
        overlay_connect_ms: overlay_connect.map(elapsed_ms),
        proxy_connect_ms: proxy_connect.map(elapsed_ms),
        error: Some(error.to_string()),
    }
}

async fn run_spoke_egress_transfer(
    args: &Args,
    direction: Direction,
    egress: Arc<rove::outbound::EgressContext>,
) -> BandwidthReport {
    run_transfer_matrix(args, direction, move |payload_bytes, timeout| {
        let egress = egress.clone();
        async move {
            let stream = open_spoke_egress_stream(&egress).await?;
            transfer_over_stream(stream, direction, payload_bytes, timeout).await
        }
    })
    .await
}

async fn run_hub_inbound_transfer(
    args: &Args,
    spoke: &netstack::NetHandle,
    target: SocketAddr,
    direction: Direction,
) -> BandwidthReport {
    let spoke = spoke.clone();
    run_transfer_matrix(args, direction, move |payload_bytes, timeout| {
        let spoke = spoke.clone();
        async move {
            let stream = spoke
                .connect(HUB_IP, HUB_PROXY_PORT)
                .await
                .context("overlay connect")?;
            let stream: BenchStream = Box::new(stream);
            let stream = http_connect_over_stream(stream, target, timeout).await?;
            transfer_over_stream(stream, direction, payload_bytes, timeout).await
        }
    })
    .await
}

async fn run_transfer_matrix<F, Fut>(
    args: &Args,
    direction: Direction,
    run_one: F,
) -> BandwidthReport
where
    F: Fn(usize, Duration) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = anyhow::Result<usize>> + Send + 'static,
{
    let payload_bytes = args.mib * 1024 * 1024;
    let run_one = Arc::new(run_one);
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(args.streams);
    for _ in 0..args.streams {
        let run_one = run_one.clone();
        let timeout = args.timeout;
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            match run_one(payload_bytes, timeout).await {
                Ok(bytes_count) => TransferSample {
                    ok: true,
                    bytes_count,
                    elapsed_ms: elapsed_ms(started.elapsed()),
                    error: None,
                },
                Err(e) => TransferSample {
                    ok: false,
                    bytes_count: 0,
                    elapsed_ms: elapsed_ms(started.elapsed()),
                    error: Some(e.to_string()),
                },
            }
        }));
    }

    let mut samples = Vec::with_capacity(args.streams);
    for task in tasks {
        samples.push(task.await.unwrap_or_else(|e| TransferSample {
            ok: false,
            bytes_count: 0,
            elapsed_ms: 0.0,
            error: Some(format!("task join: {e}")),
        }));
    }

    summarize_bandwidth(direction, args, started.elapsed(), samples)
}

async fn open_spoke_egress_stream(
    egress: &rove::outbound::EgressContext,
) -> anyhow::Result<BenchStream> {
    let decision = Decision::Via(Upstream {
        kind: UpstreamKind::Subnetra,
        addr: String::new(),
        username: None,
        password: None,
        tls: false,
        skip_cert_verify: false,
    });
    rove::outbound::connect(decision, &HUB_IP.to_string(), EGRESS_TARGET_PORT, egress)
        .await
        .map(|(stream, _egress)| stream)
        .map_err(|e| anyhow::anyhow!(e))
}

async fn request_ping(mut stream: BenchStream, timeout: Duration) -> anyhow::Result<()> {
    stream
        .write_all(b"GET /ping HTTP/1.1\r\nHost: subnetra-bench\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let (head, body) = tokio::time::timeout(timeout, read_http_head_and_remainder(&mut stream))
        .await
        .context("ping response timed out")??;
    ensure_200(&head)?;
    let expected = content_length(&head);
    let mut received = body.len();
    let mut buf = [0u8; 1024];
    while received < expected {
        let n = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .context("ping body timed out")??;
        if n == 0 {
            break;
        }
        received += n;
    }
    Ok(())
}

async fn transfer_over_stream(
    stream: BenchStream,
    direction: Direction,
    payload_bytes: usize,
    timeout: Duration,
) -> anyhow::Result<usize> {
    match direction {
        Direction::Download => download_over_stream(stream, payload_bytes, timeout).await,
        Direction::Upload => upload_over_stream(stream, payload_bytes, timeout).await,
    }
}

async fn download_over_stream(
    mut stream: BenchStream,
    payload_bytes: usize,
    timeout: Duration,
) -> anyhow::Result<usize> {
    stream
        .write_all(b"GET /download HTTP/1.1\r\nHost: subnetra-bench\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let (head, body) = tokio::time::timeout(timeout, read_http_head_and_remainder(&mut stream))
        .await
        .context("download response timed out")??;
    ensure_200(&head)?;
    let expected = content_length(&head);
    anyhow::ensure!(
        expected == payload_bytes,
        "download content-length {expected}, expected {payload_bytes}"
    );
    let mut received = body.len();
    let mut buf = vec![0u8; IO_BUF_SIZE];
    while received < expected {
        let n = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .context("download body timed out")??;
        if n == 0 {
            break;
        }
        received += n;
    }
    anyhow::ensure!(
        received == payload_bytes,
        "downloaded {received} bytes, expected {payload_bytes}"
    );
    Ok(received)
}

async fn upload_over_stream(
    mut stream: BenchStream,
    payload_bytes: usize,
    timeout: Duration,
) -> anyhow::Result<usize> {
    let req = format!(
        "POST /upload HTTP/1.1\r\nHost: subnetra-bench\r\nContent-Length: {payload_bytes}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    let mut remaining = payload_bytes;
    while remaining > 0 {
        let n = remaining.min(CHUNK.len());
        stream.write_all(&CHUNK[..n]).await?;
        remaining -= n;
        if remaining.is_multiple_of(8 * 1024 * 1024) {
            stream.flush().await?;
        }
    }
    stream.flush().await?;
    let (head, _) = tokio::time::timeout(timeout, read_http_head_and_remainder(&mut stream))
        .await
        .context("upload response timed out")??;
    ensure_200(&head)?;
    Ok(payload_bytes)
}

async fn http_connect_over_stream(
    mut stream: BenchStream,
    target: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<BenchStream> {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let head = tokio::time::timeout(timeout, rove::util::read_http_head(&mut stream, 16 * 1024))
        .await
        .context("proxy CONNECT response timed out")??;
    ensure_200(&head)?;
    Ok(stream)
}

async fn read_http_head_and_remainder<S>(stream: &mut S) -> anyhow::Result<(Vec<u8>, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    while !data.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
        anyhow::ensure!(data.len() <= 64 * 1024, "HTTP head too large");
    }
    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
        let split_at = pos + 4;
        Ok((data[..split_at].to_vec(), data[split_at..].to_vec()))
    } else {
        Ok((data, Vec::new()))
    }
}

fn ensure_200(head: &[u8]) -> anyhow::Result<()> {
    let first = String::from_utf8_lossy(head);
    let line = first.lines().next().unwrap_or("");
    anyhow::ensure!(
        line.starts_with("HTTP/1.1 200"),
        "unexpected HTTP response: {line}"
    );
    Ok(())
}

fn content_length(head: &[u8]) -> usize {
    for line in head.split(|b| *b == b'\n') {
        let line = String::from_utf8_lossy(line);
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                return value.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

async fn start_direct_http_target(payload_bytes: usize) -> anyhow::Result<TargetHandle> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle_http_target(stream, payload_bytes));
        }
    });
    Ok(TargetHandle { addr })
}

async fn start_overlay_http_target(
    port: u16,
    payload_bytes: usize,
    mtu: usize,
) -> anyhow::Result<OverlayTargetHandle> {
    let cfg = SubnetraConfig {
        enable: true,
        mode: "hub".into(),
        local_id: 1,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: format!("{HUB_IP}/24"),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: Some(mtu),
        proxy_protocol: "http".into(),
        proxy_port: port,
        peers: vec![PeerConfig {
            id: 2,
            psk: "5a".repeat(32),
            allowed_src: format!("{SPOKE_IP}/32"),
            endpoint: None,
            name: "spoke".into(),
        }],
    }
    .to_runtime()?;

    let (dp, inbound) = reactor::spawn(cfg, EPOCH).await?;
    let udp = dp.local_addr();
    let (net, mut accept_rx) = netstack::spawn(dp, inbound, HUB_IP, 24, Some(port), mtu);
    tokio::spawn(async move {
        while let Some((stream, _)) = accept_rx.recv().await {
            tokio::spawn(handle_http_target(stream, payload_bytes));
        }
    });
    Ok(OverlayTargetHandle { udp, _net: net })
}

async fn handle_http_target<S>(mut stream: S, payload_bytes: usize)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Ok((head, body)) = read_http_head_and_remainder(&mut stream).await else {
        return;
    };
    let request_line = head
        .split(|b| *b == b'\n')
        .next()
        .unwrap_or_default()
        .to_vec();

    if request_line.starts_with(b"GET /download") {
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {payload_bytes}\r\nConnection: close\r\n\r\n"
        );
        if stream.write_all(head.as_bytes()).await.is_err() {
            return;
        }
        let mut remaining = payload_bytes;
        while remaining > 0 {
            let n = remaining.min(CHUNK.len());
            if stream.write_all(&CHUNK[..n]).await.is_err() {
                return;
            }
            remaining -= n;
            if remaining.is_multiple_of(8 * 1024 * 1024) && stream.flush().await.is_err() {
                return;
            }
        }
        let _ = stream.flush().await;
    } else if request_line.starts_with(b"POST /upload") {
        let mut remaining = content_length(&head).saturating_sub(body.len());
        let mut buf = vec![0u8; IO_BUF_SIZE];
        while remaining > 0 {
            let read_len = remaining.min(IO_BUF_SIZE);
            let n = match stream.read(&mut buf[..read_len]).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            remaining -= n;
        }
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await;
    } else {
        let body = b"subnetra-benchmark-ok\n";
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.write_all(body).await;
    }
    let _ = stream.shutdown().await;
}

async fn start_hub_service(mtu: usize) -> anyhow::Result<(netstack::NetHandle, SocketAddr)> {
    let cfg = SubnetraConfig {
        enable: true,
        mode: "hub".into(),
        local_id: 1,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: format!("{HUB_IP}/24"),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: Some(mtu),
        proxy_protocol: "http".into(),
        proxy_port: HUB_PROXY_PORT,
        peers: vec![PeerConfig {
            id: 2,
            psk: "5a".repeat(32),
            allowed_src: format!("{SPOKE_IP}/32"),
            endpoint: None,
            name: "spoke".into(),
        }],
    };
    service::start(
        &cfg,
        permissive_engine(),
        rove::stats::TrafficStats::new(),
        None,
        None,
        None,
        None,
    )
    .await
}

async fn start_spoke_service(
    hub_udp: SocketAddr,
    mtu: usize,
) -> anyhow::Result<netstack::NetHandle> {
    let cfg = SubnetraConfig {
        enable: true,
        mode: "spoke".into(),
        local_id: 2,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: format!("{SPOKE_IP}/24"),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: Some(mtu),
        proxy_protocol: String::new(),
        proxy_port: 0,
        peers: vec![PeerConfig {
            id: 1,
            psk: "5a".repeat(32),
            allowed_src: "10.0.0.0/24".into(),
            endpoint: Some(hub_udp.to_string()),
            name: "overlay-hub".into(),
        }],
    };
    let (net, _) = service::start(
        &cfg,
        Engine::new(),
        rove::stats::TrafficStats::new(),
        None,
        None,
        None,
        None,
    )
    .await?;
    Ok(net)
}

async fn start_spoke_net(hub_udp: SocketAddr, mtu: usize) -> anyhow::Result<netstack::NetHandle> {
    let cfg = SubnetraConfig {
        enable: true,
        mode: "spoke".into(),
        local_id: 2,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: format!("{SPOKE_IP}/24"),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: Some(mtu),
        proxy_protocol: String::new(),
        proxy_port: 0,
        peers: vec![PeerConfig {
            id: 1,
            psk: "5a".repeat(32),
            allowed_src: "10.0.0.0/24".into(),
            endpoint: Some(hub_udp.to_string()),
            name: "hub".into(),
        }],
    }
    .to_runtime()?;
    let (dp, inbound) = reactor::spawn(cfg, EPOCH).await?;
    let (net, _accept) = netstack::spawn(dp, inbound, SPOKE_IP, 24, None, mtu);
    Ok(net)
}

fn permissive_engine() -> Arc<Engine> {
    let users = HashMap::from([(
        USERNAME.to_string(),
        RawUserV4 {
            password: PASSWORD.to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            policy: "default".to_string(),
            frontends: Default::default(),
        },
    )]);
    let routing_policies = HashMap::from([("default".to_string(), RawRoutingPolicy::default())]);

    let engine = Engine::new();
    let snapshot = Snapshot::compile(
        RawSnapshotV4 {
            schema_version: V4_SCHEMA_VERSION,
            version: 1,
            users,
            routing_policies,
            egresses: HashMap::new(),
            node_overrides: HashMap::new(),
        },
        "subnetra-bench-hub",
    )
    .expect("compile benchmark snapshot");
    engine.replace(snapshot);
    engine
}

fn summarize_latency(
    requests: usize,
    concurrency: usize,
    elapsed: Duration,
    samples: Vec<LatencySample>,
) -> LatencyReport {
    let ok = samples.iter().filter(|s| s.ok).count();
    let failed = samples.len().saturating_sub(ok);
    let total = collect_metric(&samples, |s| s.ok.then_some(s.total_ms));
    let overlay = collect_metric(&samples, |s| s.ok.then_some(s.overlay_connect_ms).flatten());
    let proxy = collect_metric(&samples, |s| s.ok.then_some(s.proxy_connect_ms).flatten());
    let first_error = samples.iter().find_map(|s| s.error.clone());
    LatencyReport {
        requests,
        concurrency,
        ok,
        failed,
        rps: ok as f64 / elapsed.as_secs_f64().max(0.001),
        total_ms: summarize_metric(total),
        overlay_connect_ms: summarize_metric(overlay),
        proxy_connect_ms: summarize_metric(proxy),
        first_error,
    }
}

fn collect_metric(
    samples: &[LatencySample],
    f: impl Fn(&LatencySample) -> Option<f64>,
) -> Vec<f64> {
    samples.iter().filter_map(f).collect()
}

fn summarize_bandwidth(
    direction: Direction,
    args: &Args,
    elapsed: Duration,
    samples: Vec<TransferSample>,
) -> BandwidthReport {
    let ok = samples.iter().filter(|s| s.ok).count();
    let failed = samples.len().saturating_sub(ok);
    let bytes_count = samples.iter().map(|s| s.bytes_count).sum::<usize>();
    let elapsed_s = elapsed.as_secs_f64().max(0.001);
    BandwidthReport {
        direction,
        streams: args.streams,
        payload_per_stream_mib: args.mib,
        ok,
        failed,
        elapsed_ms: elapsed_ms(elapsed),
        throughput_mib_s: bytes_count as f64 / 1024.0 / 1024.0 / elapsed_s,
        throughput_mbit_s: bytes_count as f64 * 8.0 / elapsed_s / 1_000_000.0,
        first_error: samples.iter().find_map(|s| s.error.clone()),
    }
}

fn summarize_metric(mut values: Vec<f64>) -> Option<MetricSummary> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    Some(MetricSummary {
        min: values[0],
        p50: percentile(&values, 0.50),
        p95: percentile(&values, 0.95),
        p99: percentile(&values, 0.99),
        max: values[values.len() - 1],
    })
}

fn percentile(values: &[f64], ratio: f64) -> f64 {
    let idx = ((values.len() as f64 * ratio).ceil() as usize)
        .saturating_sub(1)
        .min(values.len() - 1);
    values[idx]
}

fn elapsed_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn print_report(report: &ScenarioReport) {
    println!("\nscenario={} mtu={}", report.scenario.as_str(), report.mtu);
    println!(
        "  latency requests={} concurrency={} ok={} failed={} rps={:.1}",
        report.latency.requests,
        report.latency.concurrency,
        report.latency.ok,
        report.latency.failed,
        report.latency.rps
    );
    if let Some(total) = &report.latency.total_ms {
        println!(
            "  total_ms min={:.2} p50={:.2} p95={:.2} p99={:.2} max={:.2}",
            total.min, total.p50, total.p95, total.p99, total.max
        );
    }
    if let Some(connect) = &report.latency.overlay_connect_ms {
        println!(
            "  overlay_connect_ms p50={:.2} p95={:.2} p99={:.2}",
            connect.p50, connect.p95, connect.p99
        );
    }
    if let Some(connect) = &report.latency.proxy_connect_ms {
        println!(
            "  proxy_connect_ms p50={:.2} p95={:.2} p99={:.2}",
            connect.p50, connect.p95, connect.p99
        );
    }
    if let Some(error) = &report.latency.first_error {
        println!("  first_latency_error={error}");
    }
    for bandwidth in &report.bandwidth {
        println!(
            "  bandwidth direction={} streams={} payload_per_stream={}MiB ok={} failed={} elapsed={:.3}s throughput={:.1}MiB/s {:.1}Mbit/s",
            bandwidth.direction.as_str(),
            bandwidth.streams,
            bandwidth.payload_per_stream_mib,
            bandwidth.ok,
            bandwidth.failed,
            bandwidth.elapsed_ms / 1000.0,
            bandwidth.throughput_mib_s,
            bandwidth.throughput_mbit_s
        );
        if let Some(error) = &bandwidth.first_error {
            println!("    first_transfer_error={error}");
        }
    }
}

struct TargetHandle {
    addr: SocketAddr,
}

struct OverlayTargetHandle {
    udp: SocketAddr,
    _net: netstack::NetHandle,
}
