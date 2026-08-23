//! Manual egress diagnostics for the standalone `rove-hop` binary.
//!
//! This module is intentionally not wired into the proxy hot path. It performs
//! one short, read-only probe of one target and reports where egress breaks:
//! DNS, local route selection, TCP, TLS, HTTP, or optional traceroute.

use crate::tls;
use crate::util::{read_http_head, split_host_port};
use anyhow::Context;
use rustls::pki_types::ServerName;
use serde::Serialize;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::{lookup_host, TcpStream, UdpSocket};

const DEFAULT_PORT: u16 = 443;
const HTTP_HEAD_CAP: usize = 32 * 1024;

#[derive(Debug, Clone)]
pub struct EgressDiagnosticConfig {
    pub target: Target,
    pub trace: bool,
    pub timeout: Duration,
    pub max_hops: u8,
    pub node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Target {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub protocol: TargetProtocol,
    pub source: TargetSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetProtocol {
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetSource {
    RandomPreset,
    NamedPreset,
    Manual,
}

#[derive(Debug, Clone, Serialize)]
pub struct EgressDiagnosticReport {
    pub kind: &'static str,
    pub node_id: String,
    pub result: OverallResult,
    pub started_at: String,
    pub target: Target,
    pub timeout_ms: u128,
    pub dns: DnsCheck,
    pub route: RouteCheck,
    pub tcp: TcpCheck,
    pub tls: TlsCheck,
    pub http: HttpCheck,
    pub trace: TraceCheck,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallResult {
    Ok,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsCheck {
    pub status: CheckStatus,
    pub duration_ms: u128,
    pub resolver: &'static str,
    pub ips: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteCheck {
    pub status: CheckStatus,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TcpCheck {
    pub status: CheckStatus,
    pub duration_ms: u128,
    pub remote: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsCheck {
    pub status: CheckStatus,
    pub duration_ms: u128,
    pub sni: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_certificates: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpCheck {
    pub status: CheckStatus,
    pub duration_ms: u128,
    pub method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceCheck {
    pub status: CheckStatus,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub max_hops: u8,
    pub hops: Vec<TraceHop>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceHop {
    pub index: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    pub timeout: bool,
    pub raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy)]
struct PresetTarget {
    name: &'static str,
    host: &'static str,
    port: u16,
}

const PRESET_TARGETS: &[PresetTarget] = &[
    PresetTarget {
        name: "google",
        host: "www.google.com",
        port: 443,
    },
    PresetTarget {
        name: "youtube",
        host: "www.youtube.com",
        port: 443,
    },
    PresetTarget {
        name: "openai",
        host: "api.openai.com",
        port: 443,
    },
    PresetTarget {
        name: "cloudflare",
        host: "www.cloudflare.com",
        port: 443,
    },
    PresetTarget {
        name: "github",
        host: "github.com",
        port: 443,
    },
];

pub fn select_target(input: Option<&str>) -> anyhow::Result<Target> {
    match input.map(str::trim).filter(|s| !s.is_empty()) {
        Some(value) => parse_target(value),
        None => {
            let idx = random_index(PRESET_TARGETS.len());
            let preset = PRESET_TARGETS[idx];
            Ok(Target {
                name: preset.name.to_string(),
                host: preset.host.to_string(),
                port: preset.port,
                protocol: TargetProtocol::Https,
                source: TargetSource::RandomPreset,
            })
        }
    }
}

pub fn preset_names() -> Vec<&'static str> {
    PRESET_TARGETS.iter().map(|target| target.name).collect()
}

fn parse_target(value: &str) -> anyhow::Result<Target> {
    let normalized = value.trim().to_ascii_lowercase();
    let preset_key = if normalized == "cloudfalre" {
        "cloudflare"
    } else {
        normalized.as_str()
    };
    if let Some(preset) = PRESET_TARGETS
        .iter()
        .find(|target| target.name == preset_key)
    {
        return Ok(Target {
            name: preset.name.to_string(),
            host: preset.host.to_string(),
            port: preset.port,
            protocol: TargetProtocol::Https,
            source: TargetSource::NamedPreset,
        });
    }

    if value.contains("://") {
        let url = url::Url::parse(value).with_context(|| format!("parse target URL {value:?}"))?;
        let protocol = match url.scheme() {
            "http" => TargetProtocol::Http,
            "https" => TargetProtocol::Https,
            scheme => anyhow::bail!("unsupported target URL scheme {scheme:?}; use http or https"),
        };
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("target URL has no host: {value:?}"))?;
        let port = url.port_or_known_default().unwrap_or(match protocol {
            TargetProtocol::Http => 80,
            TargetProtocol::Https => DEFAULT_PORT,
        });
        return Ok(Target {
            name: host.to_string(),
            host: host.to_string(),
            port,
            protocol,
            source: TargetSource::Manual,
        });
    }

    if let Some((host, port)) = split_host_port(value) {
        anyhow::ensure!(!host.trim().is_empty(), "target host is required");
        return Ok(Target {
            name: host.trim().to_string(),
            host: host.trim().trim_matches(['[', ']']).to_string(),
            port,
            protocol: protocol_for_port(port),
            source: TargetSource::Manual,
        });
    }

    Ok(Target {
        name: value.to_string(),
        host: value.to_string(),
        port: DEFAULT_PORT,
        protocol: TargetProtocol::Https,
        source: TargetSource::Manual,
    })
}

fn protocol_for_port(port: u16) -> TargetProtocol {
    if port == 80 {
        TargetProtocol::Http
    } else {
        TargetProtocol::Https
    }
}

fn random_index(len: usize) -> usize {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    (nanos as usize) % len
}

pub async fn run(config: EgressDiagnosticConfig) -> EgressDiagnosticReport {
    let started_at = timestamp();
    let dns = check_dns(&config.target, config.timeout).await;
    let destination_ip = preferred_ip(&dns.ips);
    let route = check_route(destination_ip, config.timeout).await;
    let tcp = check_tcp(&config.target, config.timeout).await;
    let tls = check_tls(&config.target, config.timeout).await;
    let http = check_http(&config.target, config.timeout).await;
    let trace = if config.trace {
        check_trace(&config.target, config.timeout, config.max_hops).await
    } else {
        TraceCheck {
            status: CheckStatus::Skipped,
            duration_ms: 0,
            tool: None,
            max_hops: config.max_hops,
            hops: Vec::new(),
            raw: None,
            message: Some("trace disabled; pass --trace to collect hop nodes".to_string()),
        }
    };
    let result = overall_result(&dns, &route, &tcp, &tls, &http, &trace, config.trace);
    let failed_stage = first_failed_stage(&dns, &tcp, &tls, &http);
    let summary = summarize(
        result,
        &route,
        &trace,
        config.trace,
        failed_stage,
        tls.status == CheckStatus::Skipped,
    );

    EgressDiagnosticReport {
        kind: "egress_diagnostic",
        node_id: config.node_id,
        result,
        started_at,
        target: config.target,
        timeout_ms: config.timeout.as_millis(),
        dns,
        route,
        tcp,
        tls,
        http,
        trace,
        summary,
    }
}

async fn check_dns(target: &Target, timeout_duration: Duration) -> DnsCheck {
    let started = Instant::now();
    let result = tokio::time::timeout(
        timeout_duration,
        lookup_host((target.host.as_str(), target.port)),
    )
    .await;
    match result {
        Ok(Ok(addrs)) => {
            let mut seen = HashSet::new();
            let mut ips = Vec::new();
            for addr in addrs {
                if seen.insert(addr.ip()) {
                    ips.push(addr.ip());
                }
            }
            let status = if ips.is_empty() {
                CheckStatus::Failed
            } else {
                CheckStatus::Ok
            };
            let message = if ips.is_empty() {
                Some("system resolver returned no addresses".to_string())
            } else {
                None
            };
            DnsCheck {
                status,
                duration_ms: started.elapsed().as_millis(),
                resolver: "system",
                ips,
                message,
            }
        }
        Ok(Err(e)) => DnsCheck {
            status: CheckStatus::Failed,
            duration_ms: started.elapsed().as_millis(),
            resolver: "system",
            ips: Vec::new(),
            message: Some(e.to_string()),
        },
        Err(_) => DnsCheck {
            status: CheckStatus::Failed,
            duration_ms: started.elapsed().as_millis(),
            resolver: "system",
            ips: Vec::new(),
            message: Some(format!("DNS lookup timed out after {timeout_duration:?}")),
        },
    }
}

fn preferred_ip(ips: &[IpAddr]) -> Option<IpAddr> {
    ips.iter()
        .copied()
        .find(IpAddr::is_ipv4)
        .or_else(|| ips.first().copied())
}

async fn check_route(destination_ip: Option<IpAddr>, timeout_duration: Duration) -> RouteCheck {
    let started = Instant::now();
    let Some(destination_ip) = destination_ip else {
        return RouteCheck {
            status: CheckStatus::Skipped,
            duration_ms: 0,
            destination_ip: None,
            local_addr: None,
            gateway: None,
            interface: None,
            tool: None,
            raw: None,
            message: Some("route skipped because DNS produced no destination IP".to_string()),
        };
    };

    let local_addr = infer_local_addr(destination_ip, timeout_duration)
        .await
        .ok()
        .flatten();
    let route_cmd = run_route_command(destination_ip).await;
    let (status, tool, raw, mut gateway, mut interface, message) = match route_cmd {
        Some(Ok(output)) => {
            let parsed = parse_route_output(&output);
            (
                CheckStatus::Ok,
                parsed.tool,
                Some(output),
                parsed.gateway,
                parsed.interface,
                None,
            )
        }
        Some(Err(e)) => (
            CheckStatus::Failed,
            None,
            None,
            None,
            None,
            Some(e.to_string()),
        ),
        None => (
            if local_addr.is_some() {
                CheckStatus::Ok
            } else {
                CheckStatus::Skipped
            },
            None,
            None,
            None,
            None,
            Some("route command not available; used UDP local-address inference only".to_string()),
        ),
    };

    if gateway.as_deref() == Some("") {
        gateway = None;
    }
    if interface.as_deref() == Some("") {
        interface = None;
    }

    RouteCheck {
        status,
        duration_ms: started.elapsed().as_millis(),
        destination_ip: Some(destination_ip),
        local_addr: local_addr.map(|addr| addr.to_string()),
        gateway,
        interface,
        tool,
        raw,
        message,
    }
}

async fn infer_local_addr(
    destination_ip: IpAddr,
    timeout_duration: Duration,
) -> anyhow::Result<Option<SocketAddr>> {
    let bind_addr = if destination_ip.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    let destination = SocketAddr::new(destination_ip, DEFAULT_PORT);
    tokio::time::timeout(timeout_duration, socket.connect(destination)).await??;
    Ok(Some(socket.local_addr()?))
}

async fn run_route_command(destination_ip: IpAddr) -> Option<anyhow::Result<String>> {
    let ip = destination_ip.to_string();
    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "linux") {
        &[("ip", &["route", "get", ip.as_str()])]
    } else {
        &[("route", &["-n", "get", ip.as_str()])]
    };

    for (tool, args) in candidates {
        let tool = (*tool).to_string();
        let display_tool = tool.clone();
        let args = args.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        let output = tokio::task::spawn_blocking(move || Command::new(&tool).args(&args).output())
            .await
            .ok()?;
        match output {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                return Some(Ok(format!("{display_tool}: {text}")));
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Some(Err(anyhow::anyhow!(
                    "{display_tool} exited with {}: {}",
                    output.status,
                    stderr.trim()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Some(Err(e.into())),
        }
    }
    None
}

struct ParsedRoute {
    tool: Option<String>,
    gateway: Option<String>,
    interface: Option<String>,
}

fn parse_route_output(output: &str) -> ParsedRoute {
    let mut tool = output.split(':').next().map(str::to_string);
    if tool.as_deref() == Some(output) {
        tool = None;
    }
    let body = output
        .split_once(':')
        .map(|(_, rest)| rest)
        .unwrap_or(output);
    let mut gateway = None;
    let mut interface = None;

    let tokens = body.split_whitespace().collect::<Vec<_>>();
    for window in tokens.windows(2) {
        match window[0] {
            "via" | "gateway:" => gateway = Some(window[1].to_string()),
            "dev" | "interface:" => interface = Some(window[1].to_string()),
            _ => {}
        }
    }

    ParsedRoute {
        tool,
        gateway,
        interface,
    }
}

async fn check_tcp(target: &Target, timeout_duration: Duration) -> TcpCheck {
    let started = Instant::now();
    match connect_tcp(target, timeout_duration).await {
        Ok(stream) => TcpCheck {
            status: CheckStatus::Ok,
            duration_ms: started.elapsed().as_millis(),
            remote: target.address(),
            local_addr: stream.local_addr().ok().map(|addr| addr.to_string()),
            peer_addr: stream.peer_addr().ok().map(|addr| addr.to_string()),
            message: None,
        },
        Err(e) => TcpCheck {
            status: CheckStatus::Failed,
            duration_ms: started.elapsed().as_millis(),
            remote: target.address(),
            local_addr: None,
            peer_addr: None,
            message: Some(e.to_string()),
        },
    }
}

async fn check_tls(target: &Target, timeout_duration: Duration) -> TlsCheck {
    let started = Instant::now();
    if target.protocol == TargetProtocol::Http {
        return TlsCheck {
            status: CheckStatus::Skipped,
            duration_ms: started.elapsed().as_millis(),
            sni: target.host.clone(),
            version: None,
            alpn: None,
            peer_certificates: None,
            message: Some("TLS skipped because target protocol is HTTP".to_string()),
        };
    }

    let server_name = match ServerName::try_from(target.host.as_str()) {
        Ok(name) => name.to_owned(),
        Err(e) => {
            return TlsCheck {
                status: CheckStatus::Failed,
                duration_ms: started.elapsed().as_millis(),
                sni: target.host.clone(),
                version: None,
                alpn: None,
                peer_certificates: None,
                message: Some(format!("invalid TLS server name: {e}")),
            }
        }
    };
    match connect_tcp(target, timeout_duration).await {
        Ok(stream) => {
            let connector = tls::client_connector();
            match tokio::time::timeout(timeout_duration, connector.connect(server_name, stream))
                .await
            {
                Ok(Ok(stream)) => {
                    let (_, conn) = stream.get_ref();
                    TlsCheck {
                        status: CheckStatus::Ok,
                        duration_ms: started.elapsed().as_millis(),
                        sni: target.host.clone(),
                        version: conn.protocol_version().map(|v| format!("{v:?}")),
                        alpn: conn
                            .alpn_protocol()
                            .map(|v| String::from_utf8_lossy(v).to_string()),
                        peer_certificates: conn.peer_certificates().map(|certs| certs.len()),
                        message: None,
                    }
                }
                Ok(Err(e)) => TlsCheck {
                    status: CheckStatus::Failed,
                    duration_ms: started.elapsed().as_millis(),
                    sni: target.host.clone(),
                    version: None,
                    alpn: None,
                    peer_certificates: None,
                    message: Some(e.to_string()),
                },
                Err(_) => TlsCheck {
                    status: CheckStatus::Failed,
                    duration_ms: started.elapsed().as_millis(),
                    sni: target.host.clone(),
                    version: None,
                    alpn: None,
                    peer_certificates: None,
                    message: Some(format!(
                        "TLS handshake timed out after {timeout_duration:?}"
                    )),
                },
            }
        }
        Err(e) => TlsCheck {
            status: CheckStatus::Failed,
            duration_ms: started.elapsed().as_millis(),
            sni: target.host.clone(),
            version: None,
            alpn: None,
            peer_certificates: None,
            message: Some(e.to_string()),
        },
    }
}

async fn check_http(target: &Target, timeout_duration: Duration) -> HttpCheck {
    let started = Instant::now();
    let result = match target.protocol {
        TargetProtocol::Https => http_head_over_tls(target, timeout_duration).await,
        TargetProtocol::Http => http_head_plain(target, timeout_duration).await,
    };
    match result {
        Ok((head, duration_ms)) => {
            let parsed = parse_http_head(&head);
            HttpCheck {
                status: if parsed.code.is_some() {
                    CheckStatus::Ok
                } else {
                    CheckStatus::Failed
                },
                duration_ms,
                method: "HEAD",
                code: parsed.code,
                status_line: parsed.status_line,
                server: parsed.server,
                location: parsed.location,
                message: None,
            }
        }
        Err(e) => HttpCheck {
            status: CheckStatus::Failed,
            duration_ms: started.elapsed().as_millis(),
            method: "HEAD",
            code: None,
            status_line: None,
            server: None,
            location: None,
            message: Some(e.to_string()),
        },
    }
}

async fn connect_tcp(target: &Target, timeout_duration: Duration) -> anyhow::Result<TcpStream> {
    let stream = tokio::time::timeout(
        timeout_duration,
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .with_context(|| format!("TCP connect timed out after {timeout_duration:?}"))??;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn http_head_over_tls(
    target: &Target,
    timeout_duration: Duration,
) -> anyhow::Result<(Vec<u8>, u128)> {
    let started = Instant::now();
    let stream = connect_tcp(target, timeout_duration).await?;
    let server_name = ServerName::try_from(target.host.as_str())
        .with_context(|| format!("invalid TLS server name {:?}", target.host))?
        .to_owned();
    let mut stream = tokio::time::timeout(
        timeout_duration,
        tls::client_connector().connect(server_name, stream),
    )
    .await
    .with_context(|| format!("TLS handshake timed out after {timeout_duration:?}"))??;
    write_head_request(&mut stream, target).await?;
    let head = tokio::time::timeout(timeout_duration, read_http_head(&mut stream, HTTP_HEAD_CAP))
        .await
        .with_context(|| format!("HTTP read timed out after {timeout_duration:?}"))??;
    Ok((head, started.elapsed().as_millis()))
}

async fn http_head_plain(
    target: &Target,
    timeout_duration: Duration,
) -> anyhow::Result<(Vec<u8>, u128)> {
    let started = Instant::now();
    let mut stream = connect_tcp(target, timeout_duration).await?;
    write_head_request(&mut stream, target).await?;
    let head = tokio::time::timeout(timeout_duration, read_http_head(&mut stream, HTTP_HEAD_CAP))
        .await
        .with_context(|| format!("HTTP read timed out after {timeout_duration:?}"))??;
    Ok((head, started.elapsed().as_millis()))
}

async fn write_head_request<S>(stream: &mut S, target: &Target) -> anyhow::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nUser-Agent: rove-hop-doctor/{}\r\nConnection: close\r\n\r\n",
        target.host_header(),
        env!("CARGO_PKG_VERSION")
    );
    stream.write_all(request.as_bytes()).await?;
    Ok(())
}

struct ParsedHttpHead {
    code: Option<u16>,
    status_line: Option<String>,
    server: Option<String>,
    location: Option<String>,
}

fn parse_http_head(head: &[u8]) -> ParsedHttpHead {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.lines();
    let status_line = lines.next().map(str::to_string);
    let code = status_line
        .as_deref()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok());
    let mut server = None;
    let mut location = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("server") {
                server = Some(value.trim().to_string());
            } else if name.eq_ignore_ascii_case("location") {
                location = Some(value.trim().to_string());
            }
        }
    }
    ParsedHttpHead {
        code,
        status_line,
        server,
        location,
    }
}

async fn check_trace(target: &Target, timeout_duration: Duration, max_hops: u8) -> TraceCheck {
    let started = Instant::now();
    let command = trace_command(target, timeout_duration, max_hops).await;
    match command {
        Some(Ok((tool, raw))) => {
            let hops = parse_trace_hops(&raw);
            TraceCheck {
                status: if hops.is_empty() {
                    CheckStatus::Failed
                } else {
                    CheckStatus::Ok
                },
                duration_ms: started.elapsed().as_millis(),
                tool: Some(tool),
                max_hops,
                hops,
                raw: Some(raw),
                message: None,
            }
        }
        Some(Err(e)) => TraceCheck {
            status: CheckStatus::Failed,
            duration_ms: started.elapsed().as_millis(),
            tool: None,
            max_hops,
            hops: Vec::new(),
            raw: None,
            message: Some(e.to_string()),
        },
        None => TraceCheck {
            status: CheckStatus::Skipped,
            duration_ms: started.elapsed().as_millis(),
            tool: None,
            max_hops,
            hops: Vec::new(),
            raw: None,
            message: Some("no traceroute or tracepath command found".to_string()),
        },
    }
}

async fn trace_command(
    target: &Target,
    timeout_duration: Duration,
    max_hops: u8,
) -> Option<anyhow::Result<(String, String)>> {
    let wait_secs = timeout_duration.as_secs().clamp(1, 30).to_string();
    let max_hops = max_hops.to_string();
    let candidates = vec![
        (
            "traceroute".to_string(),
            vec![
                "-m".to_string(),
                max_hops.clone(),
                "-w".to_string(),
                wait_secs,
                "-q".to_string(),
                "1".to_string(),
                target.host.clone(),
            ],
        ),
        (
            "tracepath".to_string(),
            vec!["-m".to_string(), max_hops, target.host.clone()],
        ),
    ];

    for (tool, args) in candidates {
        let output = tokio::task::spawn_blocking({
            let tool = tool.clone();
            let args = args.clone();
            move || Command::new(&tool).args(&args).output()
        })
        .await
        .ok()?;
        match output {
            Ok(output) if output.status.success() => {
                let mut raw = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !stderr.trim().is_empty() {
                    raw.push_str(stderr.trim());
                }
                return Some(Ok((tool, raw.trim().to_string())));
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Some(Err(anyhow::anyhow!(
                    "{tool} exited with {}: {}",
                    output.status,
                    stderr.trim()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Some(Err(e.into())),
        }
    }
    None
}

pub fn parse_trace_hops(raw: &str) -> Vec<TraceHop> {
    raw.lines().filter_map(parse_trace_line).collect()
}

fn parse_trace_line(line: &str) -> Option<TraceHop> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let index = parts.next()?.parse::<u8>().ok()?;
    let rest = parts.collect::<Vec<_>>();
    let timeout = rest.iter().any(|part| part.contains('*'));
    let ip = rest.iter().find_map(|part| parse_ip_token(part));
    let host = rest
        .iter()
        .find(|part| {
            !part.contains('*')
                && !part.ends_with("ms")
                && parse_ip_token(part).is_none()
                && part.parse::<f64>().is_err()
        })
        .map(|part| part.trim_matches(['(', ')']).to_string());
    let rtt_ms = rest.windows(2).find_map(|window| {
        if window[1] == "ms" {
            window[0].parse::<f64>().ok()
        } else {
            None
        }
    });

    Some(TraceHop {
        index,
        ip,
        host,
        rtt_ms,
        timeout,
        raw: trimmed.to_string(),
    })
}

fn parse_ip_token(token: &str) -> Option<IpAddr> {
    token
        .trim_matches(['(', ')', '[', ']', ','])
        .parse::<IpAddr>()
        .ok()
}

fn overall_result(
    dns: &DnsCheck,
    route: &RouteCheck,
    tcp: &TcpCheck,
    tls: &TlsCheck,
    http: &HttpCheck,
    trace: &TraceCheck,
    trace_requested: bool,
) -> OverallResult {
    if dns.status == CheckStatus::Failed
        || tcp.status == CheckStatus::Failed
        || tls.status == CheckStatus::Failed
        || http.status == CheckStatus::Failed
    {
        return OverallResult::Failed;
    }
    if route.status != CheckStatus::Ok || (trace_requested && trace.status != CheckStatus::Ok) {
        return OverallResult::Degraded;
    }
    OverallResult::Ok
}

fn first_failed_stage(
    dns: &DnsCheck,
    tcp: &TcpCheck,
    tls: &TlsCheck,
    http: &HttpCheck,
) -> Option<&'static str> {
    [
        ("DNS", dns.status),
        ("TCP", tcp.status),
        ("TLS", tls.status),
        ("HTTP", http.status),
    ]
    .into_iter()
    .find(|(_, status)| *status == CheckStatus::Failed)
    .map(|(name, _)| name)
}

fn summarize(
    result: OverallResult,
    route: &RouteCheck,
    trace: &TraceCheck,
    trace_requested: bool,
    failed_stage: Option<&'static str>,
    tls_skipped: bool,
) -> String {
    match result {
        OverallResult::Ok => {
            let tls_note = if tls_skipped {
                "; TLS was skipped for HTTP target"
            } else {
                ""
            };
            if trace_requested {
                if tls_skipped {
                    return format!(
                        "DNS, route, TCP, HTTP, and trace completed successfully{tls_note}"
                    );
                }
                "DNS, route, TCP, TLS, HTTP, and trace completed successfully".to_string()
            } else {
                if tls_skipped {
                    return format!(
                        "DNS, route, TCP, and HTTP completed successfully{tls_note}; trace was not requested"
                    );
                }
                "DNS, route, TCP, TLS, and HTTP completed successfully; trace was not requested"
                    .to_string()
            }
        }
        OverallResult::Degraded => {
            let mut parts = Vec::new();
            if route.status != CheckStatus::Ok {
                parts.push("route evidence is incomplete");
            }
            if trace_requested && trace.status != CheckStatus::Ok {
                parts.push("trace did not complete");
            }
            format!(
                "egress is usable but diagnostic evidence is incomplete: {}",
                parts.join(", ")
            )
        }
        OverallResult::Failed => {
            let failed = failed_stage.unwrap_or("unknown");
            format!("egress failed at {failed}")
        }
    }
}

fn timestamp() -> String {
    chrono::Local::now().to_rfc3339()
}

impl Target {
    fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    fn host_header(&self) -> String {
        match (self.protocol, self.port) {
            (TargetProtocol::Http, 80) | (TargetProtocol::Https, 443) => self.host.clone(),
            _ => format!("{}:{}", self.host, self.port),
        }
    }
}

pub fn render_text(report: &EgressDiagnosticReport) -> String {
    let mut out = String::new();
    out.push_str("Rove Hop Egress Doctor\n");
    out.push_str(&format!("node_id: {}\n", report.node_id));
    out.push_str(&format!(
        "target: {} ({}://{}:{})\n",
        report.target.name,
        protocol_name(report.target.protocol),
        report.target.host,
        report.target.port
    ));
    out.push_str(&format!(
        "selection: {}\n",
        target_source_name(report.target.source)
    ));
    out.push_str(&format!("started_at: {}\n", report.started_at));
    out.push_str(&format!("timeout: {} ms\n", report.timeout_ms));
    out.push('\n');

    out.push_str("[DNS]\n");
    out.push_str(&format!("status: {}\n", status_name(report.dns.status)));
    out.push_str(&format!("resolver: {}\n", report.dns.resolver));
    out.push_str(&format!("duration: {} ms\n", report.dns.duration_ms));
    if report.dns.ips.is_empty() {
        out.push_str("ips: none\n");
    } else {
        for ip in &report.dns.ips {
            out.push_str(&format!("ip: {ip}\n"));
        }
    }
    append_message(&mut out, report.dns.message.as_deref());
    out.push('\n');

    out.push_str("[ROUTE]\n");
    out.push_str(&format!("status: {}\n", status_name(report.route.status)));
    out.push_str(&format!("duration: {} ms\n", report.route.duration_ms));
    append_field(&mut out, "destination_ip", report.route.destination_ip);
    append_field(&mut out, "local_addr", report.route.local_addr.as_deref());
    append_field(&mut out, "gateway", report.route.gateway.as_deref());
    append_field(&mut out, "interface", report.route.interface.as_deref());
    append_field(&mut out, "tool", report.route.tool.as_deref());
    append_message(&mut out, report.route.message.as_deref());
    append_raw(&mut out, report.route.raw.as_deref());
    out.push('\n');

    out.push_str("[TCP]\n");
    out.push_str(&format!("status: {}\n", status_name(report.tcp.status)));
    out.push_str(&format!("remote: {}\n", report.tcp.remote));
    out.push_str(&format!("duration: {} ms\n", report.tcp.duration_ms));
    append_field(&mut out, "local_addr", report.tcp.local_addr.as_deref());
    append_field(&mut out, "peer_addr", report.tcp.peer_addr.as_deref());
    append_message(&mut out, report.tcp.message.as_deref());
    out.push('\n');

    out.push_str("[TLS]\n");
    out.push_str(&format!("status: {}\n", status_name(report.tls.status)));
    out.push_str(&format!("sni: {}\n", report.tls.sni));
    out.push_str(&format!("duration: {} ms\n", report.tls.duration_ms));
    append_field(&mut out, "version", report.tls.version.as_deref());
    append_field(&mut out, "alpn", report.tls.alpn.as_deref());
    append_field(&mut out, "peer_certificates", report.tls.peer_certificates);
    append_message(&mut out, report.tls.message.as_deref());
    out.push('\n');

    out.push_str("[HTTP]\n");
    out.push_str(&format!("status: {}\n", status_name(report.http.status)));
    out.push_str(&format!("method: {}\n", report.http.method));
    out.push_str(&format!("duration: {} ms\n", report.http.duration_ms));
    append_field(&mut out, "code", report.http.code);
    append_field(&mut out, "status_line", report.http.status_line.as_deref());
    append_field(&mut out, "server", report.http.server.as_deref());
    append_field(&mut out, "location", report.http.location.as_deref());
    append_message(&mut out, report.http.message.as_deref());
    out.push('\n');

    out.push_str("[TRACE]\n");
    out.push_str(&format!("status: {}\n", status_name(report.trace.status)));
    out.push_str(&format!("max_hops: {}\n", report.trace.max_hops));
    append_field(&mut out, "tool", report.trace.tool.as_deref());
    out.push_str("hops:\n");
    if report.trace.hops.is_empty() {
        out.push_str("  none\n");
    } else {
        for hop in &report.trace.hops {
            out.push_str(&format!(
                "  {:>2}  ip={} host={} rtt={} timeout={} raw={}\n",
                hop.index,
                hop.ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                hop.host.as_deref().unwrap_or("-"),
                hop.rtt_ms
                    .map(|rtt| format!("{rtt:.3} ms"))
                    .unwrap_or_else(|| "-".to_string()),
                hop.timeout,
                hop.raw
            ));
        }
    }
    append_message(&mut out, report.trace.message.as_deref());
    append_raw(&mut out, report.trace.raw.as_deref());
    out.push('\n');

    out.push_str("[SUMMARY]\n");
    out.push_str(&format!("result: {}\n", result_name(report.result)));
    out.push_str(&format!("diagnosis: {}\n", report.summary));
    out
}

fn status_name(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Ok => "ok",
        CheckStatus::Failed => "failed",
        CheckStatus::Skipped => "skipped",
    }
}

fn result_name(result: OverallResult) -> &'static str {
    match result {
        OverallResult::Ok => "ok",
        OverallResult::Degraded => "degraded",
        OverallResult::Failed => "failed",
    }
}

fn target_source_name(source: TargetSource) -> &'static str {
    match source {
        TargetSource::RandomPreset => "random_preset",
        TargetSource::NamedPreset => "named_preset",
        TargetSource::Manual => "manual",
    }
}

fn protocol_name(protocol: TargetProtocol) -> &'static str {
    match protocol {
        TargetProtocol::Http => "http",
        TargetProtocol::Https => "https",
    }
}

fn append_field<T: std::fmt::Display>(out: &mut String, name: &str, value: Option<T>) {
    if let Some(value) = value {
        out.push_str(&format!("{name}: {value}\n"));
    }
}

fn append_message(out: &mut String, message: Option<&str>) {
    if let Some(message) = message {
        out.push_str(&format!("message: {message}\n"));
    }
}

fn append_raw(out: &mut String, raw: Option<&str>) {
    if let Some(raw) = raw.filter(|raw| !raw.trim().is_empty()) {
        out.push_str("raw:\n");
        for line in raw.lines() {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_target_supports_presets_manual_urls_and_typo_alias() {
        assert_eq!(
            select_target(Some("github")).unwrap().host,
            "github.com".to_string()
        );
        assert_eq!(
            select_target(Some("cloudfalre")).unwrap().host,
            "www.cloudflare.com".to_string()
        );
        let manual = select_target(Some("api.openai.com:8443")).unwrap();
        assert_eq!(manual.host, "api.openai.com");
        assert_eq!(manual.port, 8443);
        let url = select_target(Some("https://example.com/path")).unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 443);
    }

    #[test]
    fn parse_trace_hops_extracts_ip_host_rtt_and_timeout() {
        let hops = parse_trace_hops(
            r#"
traceroute to github.com (140.82.113.4), 20 hops max
 1  gateway.local (192.168.1.1)  1.234 ms
 2  *
 3  140.82.113.4  91.700 ms
"#,
        );

        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].index, 1);
        assert_eq!(hops[0].host.as_deref(), Some("gateway.local"));
        assert_eq!(hops[0].ip.unwrap().to_string(), "192.168.1.1");
        assert_eq!(hops[0].rtt_ms, Some(1.234));
        assert!(hops[1].timeout);
        assert_eq!(hops[2].ip.unwrap().to_string(), "140.82.113.4");
    }

    #[test]
    fn parse_route_output_handles_linux_and_bsd_shapes() {
        let linux = parse_route_output("ip: 8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.2");
        assert_eq!(linux.tool.as_deref(), Some("ip"));
        assert_eq!(linux.gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(linux.interface.as_deref(), Some("eth0"));

        let bsd = parse_route_output("route: gateway: 10.0.0.1\ninterface: en0");
        assert_eq!(bsd.tool.as_deref(), Some("route"));
        assert_eq!(bsd.gateway.as_deref(), Some("10.0.0.1"));
        assert_eq!(bsd.interface.as_deref(), Some("en0"));
    }
}
