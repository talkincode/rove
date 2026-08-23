//! Local DNS resolution benchmark for Rove's dedicated egress resolver.
//!
//! Measures end-to-end resolution latency for one transport per process
//! invocation (the resolver is a process-global `OnceLock`, so a single run
//! installs exactly one protocol). Compare protocols by invoking the example
//! several times:
//!
//! ```bash
//! # system resolver (baseline, no custom DNS installed)
//! cargo run --release --example dns-benchmark-local -- --protocol system
//! # plaintext UDP to an anti-pollution server
//! cargo run --release --example dns-benchmark-local -- \
//!     --protocol udp --server 1.1.1.1:53
//! # DNS-over-TLS (DoT)
//! cargo run --release --example dns-benchmark-local -- \
//!     --protocol tls --server 1.1.1.1:853 --server-name cloudflare-dns.com
//! # DNS-over-HTTPS (DoH)
//! cargo run --release --example dns-benchmark-local -- \
//!     --protocol https --server 1.1.1.1:443 --server-name cloudflare-dns.com
//! ```
//!
//! Caching is disabled and lookups cycle through distinct hostnames so every
//! request is a real round-trip to the server (no warm-cache shortcuts).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use rove::config::DnsConfig;
use serde::Serialize;

const DEFAULT_HOSTS: &[&str] = &[
    "example.com",
    "cloudflare.com",
    "github.com",
    "wikipedia.org",
    "mozilla.org",
    "rust-lang.org",
    "debian.org",
    "kernel.org",
    "apache.org",
    "iana.org",
];

#[derive(Debug, Clone)]
struct Args {
    protocol: String,
    servers: Vec<String>,
    server_name: String,
    doh_path: String,
    ca: String,
    insecure: bool,
    hosts: Vec<String>,
    count: usize,
    warmup: usize,
    timeout_ms: u64,
    json_out: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct DnsReport {
    protocol: String,
    servers: Vec<String>,
    server_name: Option<String>,
    hosts: usize,
    requests: usize,
    ok: usize,
    failed: usize,
    qps: f64,
    addrs_per_lookup_avg: f64,
    latency_ms: Option<MetricSummary>,
    first_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct MetricSummary {
    min: f64,
    p50: f64,
    p90: f64,
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
    // Encrypted transports need the process crypto provider installed first.
    rove::tls::init_crypto();

    let args = Args::parse()?;

    // Install the requested transport. "system" leaves the global resolver
    // unset so `resolver::resolve` falls back to the OS resolver.
    let is_system = args.protocol.eq_ignore_ascii_case("system");
    if !is_system {
        let cfg = DnsConfig {
            servers: args.servers.clone(),
            protocol: args.protocol.clone(),
            timeout_ms: args.timeout_ms,
            cache_size: 0,
            tls_server_name: args.server_name.clone(),
            doh_path: args.doh_path.clone(),
            tls_ca: args.ca.clone(),
            tls_insecure: args.insecure,
            ..Default::default()
        };
        let settings = cfg.to_settings()?;
        rove::resolver::init(&settings)?;
        anyhow::ensure!(
            rove::resolver::is_custom(),
            "custom resolver failed to install"
        );
    }

    println!(
        "dns-benchmark protocol={} custom={} servers={:?} hosts={} requests={}",
        args.protocol,
        rove::resolver::is_custom(),
        args.servers,
        args.hosts.len(),
        args.count
    );

    // Warmup (unmeasured): confirms reachability and primes connections.
    for i in 0..args.warmup {
        let host = &args.hosts[i % args.hosts.len()];
        let _ = rove::resolver::resolve(host, 443).await;
    }

    let mut samples = Vec::with_capacity(args.count);
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut addr_total = 0usize;
    let mut first_error: Option<String> = None;

    let wall = Instant::now();
    for i in 0..args.count {
        let host = &args.hosts[i % args.hosts.len()];
        let started = Instant::now();
        match rove::resolver::resolve(host, 443).await {
            Ok(addrs) => {
                samples.push(elapsed_ms(started.elapsed()));
                addr_total += addrs.len();
                ok += 1;
            }
            Err(e) => {
                failed += 1;
                if first_error.is_none() {
                    first_error = Some(format!("{host}: {e}"));
                }
            }
        }
    }
    let wall_s = wall.elapsed().as_secs_f64();

    let report = DnsReport {
        protocol: args.protocol.clone(),
        servers: args.servers.clone(),
        server_name: (!args.server_name.is_empty()).then(|| args.server_name.clone()),
        hosts: args.hosts.len(),
        requests: args.count,
        ok,
        failed,
        qps: if wall_s > 0.0 {
            ok as f64 / wall_s
        } else {
            0.0
        },
        addrs_per_lookup_avg: if ok > 0 {
            addr_total as f64 / ok as f64
        } else {
            0.0
        },
        latency_ms: summarize_metric(samples),
        first_error,
    };

    print_report(&report);

    if let Some(path) = &args.json_out {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(path, json)?;
        println!("wrote {}", path.display());
    }

    Ok(())
}

fn print_report(report: &DnsReport) {
    println!(
        "\nprotocol={} ok={} failed={} qps={:.1} addrs/lookup={:.1}",
        report.protocol, report.ok, report.failed, report.qps, report.addrs_per_lookup_avg
    );
    if let Some(m) = &report.latency_ms {
        println!(
            "  latency_ms min={:.2} p50={:.2} p90={:.2} p95={:.2} p99={:.2} max={:.2}",
            m.min, m.p50, m.p90, m.p95, m.p99, m.max
        );
    }
    if let Some(err) = &report.first_error {
        println!("  first_error={err}");
    }
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let mut parsed = Args {
            protocol: "system".to_string(),
            servers: Vec::new(),
            server_name: String::new(),
            doh_path: String::new(),
            ca: String::new(),
            insecure: false,
            hosts: Vec::new(),
            count: 30,
            warmup: 3,
            timeout_ms: 5000,
            json_out: None,
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            let mut value = |current: &str| -> anyhow::Result<String> {
                args.next()
                    .ok_or_else(|| anyhow::anyhow!("missing value for {current}"))
            };
            match arg.as_str() {
                "--protocol" => parsed.protocol = value(&arg)?,
                "--server" => parsed.servers.push(value(&arg)?),
                "--server-name" => parsed.server_name = value(&arg)?,
                "--doh-path" => parsed.doh_path = value(&arg)?,
                "--ca" => parsed.ca = value(&arg)?,
                "--insecure" => parsed.insecure = true,
                "--host" => parsed.hosts.push(value(&arg)?),
                "--count" => parsed.count = value(&arg)?.parse()?,
                "--warmup" => parsed.warmup = value(&arg)?.parse()?,
                "--timeout-ms" => parsed.timeout_ms = value(&arg)?.parse()?,
                "--json-out" => parsed.json_out = Some(PathBuf::from(value(&arg)?)),
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument: {other}"),
            }
        }

        if parsed.hosts.is_empty() {
            parsed.hosts = DEFAULT_HOSTS.iter().map(|s| s.to_string()).collect();
        }
        anyhow::ensure!(parsed.count > 0, "--count must be > 0");

        let system = parsed.protocol.eq_ignore_ascii_case("system");
        if !system {
            anyhow::ensure!(
                !parsed.servers.is_empty(),
                "--protocol {} requires at least one --server",
                parsed.protocol
            );
        }
        Ok(parsed)
    }
}

fn print_usage() {
    eprintln!(
        "dns-benchmark-local — measure egress DNS resolution latency\n\
         \n\
         USAGE:\n\
         \x20  cargo run --release --example dns-benchmark-local -- [OPTIONS]\n\
         \n\
         OPTIONS:\n\
         \x20  --protocol NAME      system|udp|tcp|tls|https (default system)\n\
         \x20  --server ADDR        nameserver ip:port, repeatable (required unless system)\n\
         \x20  --server-name NAME   TLS SNI / cert name (required for tls,https)\n\
         \x20  --doh-path PATH      DoH query path (default /dns-query)\n\
         \x20  --ca PATH            PEM CA bundle to trust for tls,https\n\
         \x20  --insecure           accept any DoT/DoH cert (testing only)\n\
         \x20  --host NAME          hostname to resolve, repeatable (defaults to a 10-host set)\n\
         \x20  --count N            measured lookups, default 30\n\
         \x20  --warmup N           unmeasured warmup lookups, default 3\n\
         \x20  --timeout-ms MS      per-query timeout, default 5000\n\
         \x20  --json-out PATH      write JSON report"
    );
}

fn summarize_metric(mut values: Vec<f64>) -> Option<MetricSummary> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    Some(MetricSummary {
        min: values[0],
        p50: percentile(&values, 0.50),
        p90: percentile(&values, 0.90),
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
