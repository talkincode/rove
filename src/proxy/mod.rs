//! Standalone hop-node proxy server.
//!
//! This module deliberately does not use the control-plane snapshot, policy
//! engine, MQTT operations channel, or per-user limits. It is a small direct
//! egress proxy with explicit authentication, intended to be run as the
//! secondary/hop node for a Rove edge.
//!
//! It shares the same structured JSONL access log as the main edge node (see
//! `crate::access_log`): every completed connection (success or failure) can
//! optionally be recorded with the same schema, so ops can grep hop-node
//! connections with the same tooling. `snapshot_version` is always `0` here
//! since hop nodes have no control-plane snapshot to version.

use crate::access_log::AccessLogger;
use crate::io::{splice, IoStream};
use crate::stats::TrafficStats;
use crate::trace::{TraceCandidate, TraceResult};
use crate::util::{read_http_head, split_host_port};
use base64::Engine as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

pub const DEFAULT_USERNAME: &str = "rove";
pub const DEFAULT_PASSWORD: &str = "rove";

const HTTP_HEAD_CAP: usize = 16 * 1024;
const SOCKS_VERSION: u8 = 0x05;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// HTTP CONNECT over TLS.
    Https,
    /// Plain RFC 1928/1929 SOCKS5.
    Socks5,
    /// RFC 1928/1929 SOCKS5 wrapped in server-side TLS.
    Socks5Tls,
}

#[derive(Debug, Clone)]
pub struct TlsFiles {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct Listener {
    pub name: String,
    pub protocol: Protocol,
    pub listen: String,
    pub tls: Option<TlsFiles>,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> anyhow::Result<Self> {
        let username = username.into();
        let password = password.into();
        anyhow::ensure!(!username.is_empty(), "hop username must not be empty");
        anyhow::ensure!(!password.is_empty(), "hop password must not be empty");
        Ok(Credentials { username, password })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn uses_default(&self) -> bool {
        self.username == DEFAULT_USERNAME && self.password == DEFAULT_PASSWORD
    }
}

impl Default for Credentials {
    fn default() -> Self {
        Credentials {
            username: DEFAULT_USERNAME.to_string(),
            password: DEFAULT_PASSWORD.to_string(),
        }
    }
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Https => "https",
            Protocol::Socks5 => "socks5",
            Protocol::Socks5Tls => "socks5tls",
        }
    }

    fn requires_tls(self) -> bool {
        matches!(self, Protocol::Https | Protocol::Socks5Tls)
    }
}

impl Listener {
    pub fn https(name: impl Into<String>, listen: impl Into<String>, tls: TlsFiles) -> Self {
        Listener {
            name: name.into(),
            protocol: Protocol::Https,
            listen: listen.into(),
            tls: Some(tls),
        }
    }

    pub fn socks5(name: impl Into<String>, listen: impl Into<String>) -> Self {
        Listener {
            name: name.into(),
            protocol: Protocol::Socks5,
            listen: listen.into(),
            tls: None,
        }
    }

    pub fn socks5tls(name: impl Into<String>, listen: impl Into<String>, tls: TlsFiles) -> Self {
        Listener {
            name: name.into(),
            protocol: Protocol::Socks5Tls,
            listen: listen.into(),
            tls: Some(tls),
        }
    }
}

pub async fn run_listener(
    cfg: Listener,
    credentials: Credentials,
    access_log: Option<Arc<AccessLogger>>,
    stats: Arc<TrafficStats>,
) -> anyhow::Result<()> {
    let acceptor = match (&cfg.tls, cfg.protocol.requires_tls()) {
        (Some(tls), _) => Some(crate::tls::server_acceptor(&tls.cert, &tls.key)?),
        (None, true) => anyhow::bail!(
            "hop listener {} ({}) requires --tls-cert and --tls-key",
            cfg.name,
            cfg.protocol.as_str()
        ),
        (None, false) => None,
    };

    let listener = TcpListener::bind(&cfg.listen).await?;
    stats.register_listener(&cfg.name);
    info!(
        listener = %cfg.name,
        protocol = cfg.protocol.as_str(),
        tls = acceptor.is_some(),
        addr = %cfg.listen,
        "hop proxy listening"
    );

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(listener = %cfg.name, error = %e, "hop proxy accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let protocol = cfg.protocol;
        let listener_name = cfg.name.clone();
        let credentials = credentials.clone();
        let access_log = access_log.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(
                stream,
                acceptor,
                protocol,
                credentials,
                listener_name.clone(),
                access_log,
                stats,
                peer,
            )
            .await
            {
                debug!(listener = %listener_name, peer = %peer, error = %e, "hop proxy connection ended");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_conn(
    stream: TcpStream,
    acceptor: Option<TlsAcceptor>,
    protocol: Protocol,
    credentials: Credentials,
    listener: String,
    access_log: Option<Arc<AccessLogger>>,
    stats: Arc<TrafficStats>,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let _ = stream.set_nodelay(true);
    match (acceptor, protocol) {
        (Some(acceptor), Protocol::Https) => {
            serve_https(
                acceptor.accept(stream).await?,
                &credentials,
                &listener,
                access_log.as_ref(),
                &stats,
                peer,
            )
            .await
        }
        (Some(acceptor), Protocol::Socks5Tls) => {
            serve_socks5(
                acceptor.accept(stream).await?,
                &credentials,
                &listener,
                Protocol::Socks5Tls.as_str(),
                access_log.as_ref(),
                &stats,
                peer,
            )
            .await
        }
        (None, Protocol::Socks5) => {
            serve_socks5(
                stream,
                &credentials,
                &listener,
                Protocol::Socks5.as_str(),
                access_log.as_ref(),
                &stats,
                peer,
            )
            .await
        }
        (Some(_), Protocol::Socks5) => anyhow::bail!("plain socks5 listener unexpectedly has TLS"),
        (None, Protocol::Https | Protocol::Socks5Tls) => {
            anyhow::bail!("TLS listener started without acceptor")
        }
    }
}

/// Fields describing how one hop connection ended, for `record_access`.
/// Mirrors `inbound::http::TraceFields` / `inbound::socks5::TraceFields`,
/// trimmed to what the hop binary can actually know (no policy engine, no
/// per-user snapshot).
struct HopOutcome<'a> {
    username: Option<String>,
    target_host: Option<String>,
    target_port: Option<u16>,
    decision: Option<&'static str>,
    result: TraceResult,
    failure_stage: Option<&'a str>,
    message: Option<&'a str>,
    bytes_up: u64,
    bytes_down: u64,
}

impl Default for HopOutcome<'_> {
    fn default() -> Self {
        HopOutcome {
            username: None,
            target_host: None,
            target_port: None,
            decision: None,
            result: TraceResult::Error,
            failure_stage: None,
            message: None,
            bytes_up: 0,
            bytes_down: 0,
        }
    }
}

/// Records one completed hop connection to the shared JSONL access log, if
/// configured. `snapshot_version` is always `0`: the hop binary has no
/// control-plane snapshot to version.
fn record_access(
    access_log: Option<&Arc<AccessLogger>>,
    listener: &str,
    protocol: &str,
    started: Instant,
    peer: SocketAddr,
    outcome: HopOutcome<'_>,
) {
    let Some(access_log) = access_log else {
        return;
    };
    let candidate = TraceCandidate {
        listener: listener.to_string(),
        protocol: protocol.to_string(),
        client_addr: Some(peer.to_string()),
        username: outcome.username,
        target_host: outcome.target_host,
        target_port: outcome.target_port,
        traffic: None,
        decision: outcome.decision.map(str::to_string),
        egress: None,
        chain_member: None,
        attempts: None,
        result: outcome.result,
        failure_stage: outcome.failure_stage.map(str::to_string),
        message: outcome.message.map(str::to_string),
        snapshot_version: 0,
        duration_ms: started.elapsed().as_millis(),
    };
    access_log.record(&candidate, outcome.bytes_up, outcome.bytes_down);
}

async fn serve_https<S: IoStream>(
    mut stream: S,
    credentials: &Credentials,
    listener: &str,
    access_log: Option<&Arc<AccessLogger>>,
    stats: &TrafficStats,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let _connection_guard = stats.track_listener(listener);
    let started = Instant::now();
    let head = read_http_head(&mut stream, HTTP_HEAD_CAP).await?;
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default();
    let target = request_parts.next().unwrap_or_default();
    let parsed_target = split_host_port(target);

    let mut proxy_auth = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("proxy-authorization") {
                proxy_auth = Some(value.trim());
            }
        }
    }

    if !method.eq_ignore_ascii_case("CONNECT") {
        respond_http(&mut stream, "405 Method Not Allowed", "").await?;
        record_access(
            access_log,
            listener,
            Protocol::Https.as_str(),
            started,
            peer,
            HopOutcome {
                failure_stage: Some("parse"),
                message: Some("method not allowed"),
                ..HopOutcome::default()
            },
        );
        return Ok(());
    }

    let attempted_user = parse_proxy_auth(proxy_auth).map(|(user, _)| user);
    if !basic_auth_ok(proxy_auth, credentials) {
        respond_http(
            &mut stream,
            "407 Proxy Authentication Required",
            "Proxy-Authenticate: Basic realm=\"rove-hop\"\r\n",
        )
        .await?;
        let (target_host, target_port) = parsed_target
            .clone()
            .map(|(h, p)| (Some(h), Some(p)))
            .unwrap_or((None, None));
        record_access(
            access_log,
            listener,
            Protocol::Https.as_str(),
            started,
            peer,
            HopOutcome {
                username: attempted_user,
                target_host,
                target_port,
                failure_stage: Some("auth"),
                message: Some("proxy authentication required"),
                ..HopOutcome::default()
            },
        );
        return Ok(());
    }

    let Some((host, port)) = parsed_target else {
        respond_http(&mut stream, "400 Bad Request", "").await?;
        record_access(
            access_log,
            listener,
            Protocol::Https.as_str(),
            started,
            peer,
            HopOutcome {
                username: Some(credentials.username().to_string()),
                failure_stage: Some("parse"),
                message: Some("bad connect target"),
                ..HopOutcome::default()
            },
        );
        return Ok(());
    };

    let outbound = match crate::resolver::tcp_connect(host.as_str(), port).await {
        Ok(s) => s,
        Err(e) => {
            debug!(target = %target, error = %e, "hop https connect failed");
            respond_http(&mut stream, "502 Bad Gateway", "").await?;
            record_access(
                access_log,
                listener,
                Protocol::Https.as_str(),
                started,
                peer,
                HopOutcome {
                    username: Some(credentials.username().to_string()),
                    target_host: Some(host),
                    target_port: Some(port),
                    failure_stage: Some("outbound"),
                    message: Some("upstream connect failed"),
                    ..HopOutcome::default()
                },
            );
            return Ok(());
        }
    };
    let _ = outbound.set_nodelay(true);

    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    // Hop egress is always a direct connection; the guard keeps the SNMP
    // egress table's active gauge honest for the tunnel's lifetime.
    let _egress_guard = stats.track_egress("direct");
    let splice_result = splice(stream, outbound, 0, 0).await;
    let (result, stage, message, bytes_up, bytes_down) = match &splice_result {
        Ok(stats) => (
            TraceResult::Ok,
            None,
            None,
            stats.bytes_up,
            stats.bytes_down,
        ),
        Err(_) => (
            TraceResult::Error,
            Some("splice"),
            Some("tunnel io failed"),
            0,
            0,
        ),
    };
    stats.record_listener_bytes(listener, bytes_up, bytes_down);
    stats.record_egress_bytes("direct", bytes_up, bytes_down);
    record_access(
        access_log,
        listener,
        Protocol::Https.as_str(),
        started,
        peer,
        HopOutcome {
            username: Some(credentials.username().to_string()),
            target_host: Some(host),
            target_port: Some(port),
            decision: Some("direct"),
            result,
            failure_stage: stage,
            message,
            bytes_up,
            bytes_down,
        },
    );
    splice_result?;
    Ok(())
}

async fn respond_http<S: IoStream>(
    stream: &mut S,
    status: &str,
    extra: &str,
) -> std::io::Result<()> {
    let msg = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(msg.as_bytes()).await
}

async fn serve_socks5<S: IoStream>(
    mut stream: S,
    credentials: &Credentials,
    listener: &str,
    protocol: &str,
    access_log: Option<&Arc<AccessLogger>>,
    stats: &TrafficStats,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let _connection_guard = stats.track_listener(listener);
    let started = Instant::now();
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION {
        record_access(
            access_log,
            listener,
            protocol,
            started,
            peer,
            HopOutcome {
                failure_stage: Some("parse"),
                message: Some("bad socks version"),
                ..HopOutcome::default()
            },
        );
        return Ok(());
    }

    let mut methods = vec![0u8; header[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x02) {
        stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        record_access(
            access_log,
            listener,
            protocol,
            started,
            peer,
            HopOutcome {
                failure_stage: Some("auth"),
                message: Some("username/password auth method not offered"),
                ..HopOutcome::default()
            },
        );
        return Ok(());
    }
    stream.write_all(&[SOCKS_VERSION, 0x02]).await?;

    let (auth_ok, attempted_user) = socks5_auth_ok(&mut stream, credentials).await?;
    if !auth_ok {
        stream.write_all(&[0x01, 0x01]).await?;
        record_access(
            access_log,
            listener,
            protocol,
            started,
            peer,
            HopOutcome {
                username: attempted_user,
                failure_stage: Some("auth"),
                message: Some("authentication failed"),
                ..HopOutcome::default()
            },
        );
        return Ok(());
    }
    stream.write_all(&[0x01, 0x00]).await?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != SOCKS_VERSION || request[1] != 0x01 {
        reply_socks5(&mut stream, 0x07).await?;
        record_access(
            access_log,
            listener,
            protocol,
            started,
            peer,
            HopOutcome {
                username: Some(credentials.username().to_string()),
                failure_stage: Some("parse"),
                message: Some("unsupported socks command"),
                ..HopOutcome::default()
            },
        );
        return Ok(());
    }

    let host = match request[3] {
        0x01 => {
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            let len = read_u8(&mut stream).await? as usize;
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        0x04 => {
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            Ipv6Addr::from(addr).to_string()
        }
        _ => {
            reply_socks5(&mut stream, 0x08).await?;
            record_access(
                access_log,
                listener,
                protocol,
                started,
                peer,
                HopOutcome {
                    username: Some(credentials.username().to_string()),
                    failure_stage: Some("parse"),
                    message: Some("unsupported address type"),
                    ..HopOutcome::default()
                },
            );
            return Ok(());
        }
    };
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    let outbound = match crate::resolver::tcp_connect(host.as_str(), port).await {
        Ok(s) => s,
        Err(e) => {
            debug!(target = %format!("{host}:{port}"), error = %e, "hop socks5 connect failed");
            reply_socks5(&mut stream, 0x05).await?;
            record_access(
                access_log,
                listener,
                protocol,
                started,
                peer,
                HopOutcome {
                    username: Some(credentials.username().to_string()),
                    target_host: Some(host),
                    target_port: Some(port),
                    failure_stage: Some("outbound"),
                    message: Some("upstream connect failed"),
                    ..HopOutcome::default()
                },
            );
            return Ok(());
        }
    };
    let _ = outbound.set_nodelay(true);

    reply_socks5(&mut stream, 0x00).await?;
    // Hop egress is always a direct connection; the guard keeps the SNMP
    // egress table's active gauge honest for the tunnel's lifetime.
    let _egress_guard = stats.track_egress("direct");
    let splice_result = splice(stream, outbound, 0, 0).await;
    let (result, stage, message, bytes_up, bytes_down) = match &splice_result {
        Ok(stats) => (
            TraceResult::Ok,
            None,
            None,
            stats.bytes_up,
            stats.bytes_down,
        ),
        Err(_) => (
            TraceResult::Error,
            Some("splice"),
            Some("tunnel io failed"),
            0,
            0,
        ),
    };
    stats.record_listener_bytes(listener, bytes_up, bytes_down);
    stats.record_egress_bytes("direct", bytes_up, bytes_down);
    record_access(
        access_log,
        listener,
        protocol,
        started,
        peer,
        HopOutcome {
            username: Some(credentials.username().to_string()),
            target_host: Some(host),
            target_port: Some(port),
            decision: Some("direct"),
            result,
            failure_stage: stage,
            message,
            bytes_up,
            bytes_down,
        },
    );
    splice_result?;
    Ok(())
}

async fn socks5_auth_ok<S>(
    stream: &mut S,
    credentials: &Credentials,
) -> std::io::Result<(bool, Option<String>)>
where
    S: AsyncRead + Unpin,
{
    let version = read_u8(stream).await?;
    if version != 0x01 {
        return Ok((false, None));
    }
    let user_len = read_u8(stream).await? as usize;
    let mut user = vec![0u8; user_len];
    stream.read_exact(&mut user).await?;
    let pass_len = read_u8(stream).await? as usize;
    let mut pass = vec![0u8; pass_len];
    stream.read_exact(&mut pass).await?;

    let user = String::from_utf8_lossy(&user).to_string();
    let pass = String::from_utf8_lossy(&pass);
    let ok = credentials_ok(&user, &pass, credentials);
    Ok((ok, Some(user)))
}

async fn reply_socks5<S: IoStream>(stream: &mut S, rep: u8) -> std::io::Result<()> {
    stream
        .write_all(&[SOCKS_VERSION, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

async fn read_u8<S>(stream: &mut S) -> std::io::Result<u8>
where
    S: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    stream.read_exact(&mut byte).await?;
    Ok(byte[0])
}

/// Decodes a `Proxy-Authorization: Basic ...` header value into a
/// `(username, password)` pair, regardless of whether the credentials are
/// actually valid. Used both for the real auth check and to attach the
/// attempted username to access-log records on auth failure.
fn parse_proxy_auth(value: Option<&str>) -> Option<(String, String)> {
    let value = value?;
    let b64 = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

fn basic_auth_ok(value: Option<&str>, credentials: &Credentials) -> bool {
    match parse_proxy_auth(value) {
        Some((user, pass)) => credentials_ok(&user, &pass, credentials),
        None => false,
    }
}

fn credentials_ok(username: &str, password: &str, credentials: &Credentials) -> bool {
    constant_time_eq(username, credentials.username())
        & constant_time_eq(password, &credentials.password)
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();

    for i in 0..len {
        let a = left.get(i).copied().unwrap_or(0);
        let b = right.get(i).copied().unwrap_or(0);
        diff |= usize::from(a ^ b);
    }

    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_log::AccessLogger;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    #[test]
    fn credentials_match_only_exact_pair() {
        let credentials = Credentials::new("alice", "secret").unwrap();

        assert!(credentials_ok("alice", "secret", &credentials));
        assert!(!credentials_ok("wrong", "secret", &credentials));
        assert!(!credentials_ok("alice", "wrong", &credentials));
    }

    #[test]
    fn basic_auth_accepts_configured_credentials() {
        let credentials = Credentials::new("alice", "secret").unwrap();
        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");

        assert!(basic_auth_ok(Some(&format!("Basic {token}")), &credentials));
        assert!(!basic_auth_ok(Some("Basic not-base64"), &credentials));
        assert!(!basic_auth_ok(None, &credentials));
    }

    #[test]
    fn parse_proxy_auth_extracts_username_even_when_password_is_wrong() {
        let token = base64::engine::general_purpose::STANDARD.encode("alice:wrong-password");
        let (user, pass) = parse_proxy_auth(Some(&format!("Basic {token}"))).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "wrong-password");
        assert!(parse_proxy_auth(None).is_none());
        assert!(parse_proxy_auth(Some("Basic not-base64")).is_none());
    }

    #[test]
    fn credentials_reject_empty_values() {
        assert!(Credentials::new("", "secret").is_err());
        assert!(Credentials::new("alice", "").is_err());
    }

    #[test]
    fn tls_requirement_matches_protocol() {
        assert!(Protocol::Https.requires_tls());
        assert!(Protocol::Socks5Tls.requires_tls());
        assert!(!Protocol::Socks5.requires_tls());
        assert_eq!(Protocol::Https.as_str(), "https");
        assert_eq!(Protocol::Socks5.as_str(), "socks5");
        assert_eq!(Protocol::Socks5Tls.as_str(), "socks5tls");
    }

    #[tokio::test]
    async fn https_rejects_invalid_methods_auth_and_targets() {
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_https(
                server,
                &Credentials::default(),
                "test-https",
                None,
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let response = read_response_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 405"));
        task.await.unwrap().unwrap();

        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_https(
                server,
                &Credentials::default(),
                "test-https",
                None,
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let response = read_response_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 407"));
        task.await.unwrap().unwrap();

        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_https(
                server,
                &Credentials::default(),
                "test-https",
                None,
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        let token = auth_header();
        client
            .write_all(
                format!(
                    "CONNECT missing-port HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_response_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 400"));
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn https_tunnels_bytes_after_auth() {
        let (target_addr, target_task) = start_echo_server().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_https(
                server,
                &Credentials::default(),
                "test-https",
                None,
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        let token = auth_header();

        client
            .write_all(
                format!(
                    "CONNECT {target_addr} HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_response_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"));

        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        target_task.await.unwrap();
    }

    #[tokio::test]
    async fn https_access_log_records_successful_tunnel_with_username_and_bytes() {
        let (access_log, mut rx) = AccessLogger::for_test();
        let (target_addr, target_task) = start_echo_server().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_https(
                server,
                &Credentials::default(),
                "hop-https",
                Some(&access_log),
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        let token = auth_header();

        client
            .write_all(
                format!(
                    "CONNECT {target_addr} HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_response_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"));

        client.write_all(b"ping-ping").await.unwrap();
        let mut echoed = [0u8; 9];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping-ping");

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        target_task.await.unwrap();

        let record = rx.try_recv().expect("expected one access log record");
        assert_eq!(record.listener, "hop-https");
        assert_eq!(record.protocol, "https");
        assert_eq!(record.username.as_deref(), Some(DEFAULT_USERNAME));
        assert_eq!(record.decision.as_deref(), Some("direct"));
        assert_eq!(record.result, "ok");
        assert_eq!(record.client_addr.as_deref(), Some("203.0.113.30:33333"));
        assert!(record.bytes_up >= 9);
        assert!(record.bytes_down >= 9);
    }

    #[tokio::test]
    async fn https_active_connection_gauge_reflects_open_tunnel_and_clears_on_close() {
        let (access_log, mut rx) = AccessLogger::for_test();
        let stats = TrafficStats::new();
        let (target_addr, target_task) = start_echo_server().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let gauge_log = access_log.clone();
        let task_stats = stats.clone();
        let task = tokio::spawn(async move {
            serve_https(
                server,
                &Credentials::default(),
                "hop-https",
                Some(&gauge_log),
                &task_stats,
                test_peer(),
            )
            .await
        });
        let token = auth_header();

        client
            .write_all(
                format!(
                    "CONNECT {target_addr} HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_response_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200"));

        // Tunnel is open end-to-end: the listener's and egress's active
        // gauges reflect the one in-flight connection, fed by the
        // `TrafficStats` guards held for the lifetime of `serve_https()`.
        let active = |rows: Vec<crate::stats::StatsRow>, name: &str| {
            rows.into_iter().find(|r| r.name == name).map(|r| r.active)
        };
        assert_eq!(active(stats.listener_rows(), "hop-https"), Some(1));
        assert_eq!(active(stats.egress_rows(), "direct"), Some(1));

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        target_task.await.unwrap();

        // Connection fully closed: gauge guards dropped, back to zero, and
        // byte totals folded into both dimensions identically.
        assert_eq!(active(stats.listener_rows(), "hop-https"), Some(0));
        assert_eq!(active(stats.egress_rows(), "direct"), Some(0));
        let record = rx.try_recv().expect("expected one access log record");
        assert_eq!(record.result, "ok");
        let listener_row = stats
            .listener_rows()
            .into_iter()
            .find(|r| r.name == "hop-https")
            .unwrap();
        assert_eq!(listener_row.bytes_up_total, record.bytes_up);
        assert_eq!(listener_row.bytes_down_total, record.bytes_down);
    }

    #[tokio::test]
    async fn https_access_log_records_auth_failure_without_leaking_password() {
        let (access_log, mut rx) = AccessLogger::for_test();
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_https(
                server,
                &Credentials::default(),
                "hop-https",
                Some(&access_log),
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let response = read_response_head(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 407"));
        task.await.unwrap().unwrap();

        let record = rx.try_recv().expect("expected one access log record");
        assert_eq!(record.failure_stage.as_deref(), Some("auth"));
        assert_eq!(record.target_host.as_deref(), Some("example.com"));
        let line = String::from_utf8(serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(!line.contains(DEFAULT_PASSWORD));
    }

    #[tokio::test]
    async fn socks5_rejects_missing_auth_and_bad_credentials() {
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_socks5(
                server,
                &Credentials::default(),
                "test-socks5",
                "socks5",
                None,
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0xFF]);
        task.await.unwrap().unwrap();

        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_socks5(
                server,
                &Credentials::default(),
                "test-socks5",
                "socks5",
                None,
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);
        client
            .write_all(&[0x01, 5, b'w', b'r', b'o', b'n', b'g', 3, b'b', b'a', b'd'])
            .await
            .unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [0x01, 0x01]);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn socks5_access_log_records_attempted_username_on_auth_failure() {
        let (access_log, mut rx) = AccessLogger::for_test();
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_socks5(
                server,
                &Credentials::default(),
                "hop-socks5",
                "socks5",
                Some(&access_log),
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);
        client
            .write_all(&[0x01, 5, b'w', b'r', b'o', b'n', b'g', 3, b'b', b'a', b'd'])
            .await
            .unwrap();
        let mut auth = [0u8; 2];
        client.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [0x01, 0x01]);
        task.await.unwrap().unwrap();

        let record = rx.try_recv().expect("expected one access log record");
        assert_eq!(record.failure_stage.as_deref(), Some("auth"));
        assert_eq!(record.username.as_deref(), Some("wrong"));
    }

    #[tokio::test]
    async fn socks5_reports_unsupported_command_and_address_type() {
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_socks5(
                server,
                &Credentials::default(),
                "test-socks5",
                "socks5",
                None,
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        authenticate_socks5(&mut client).await;
        client.write_all(&[0x05, 0x03, 0x00, 0x01]).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x07);
        task.await.unwrap().unwrap();

        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_socks5(
                server,
                &Credentials::default(),
                "test-socks5",
                "socks5",
                None,
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        authenticate_socks5(&mut client).await;
        client.write_all(&[0x05, 0x01, 0x00, 0x09]).await.unwrap();
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x08);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn socks5_tunnels_domain_targets_after_auth() {
        let (target_addr, target_task) = start_echo_server().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_socks5(
                server,
                &Credentials::default(),
                "test-socks5",
                "socks5",
                None,
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        authenticate_socks5(&mut client).await;

        let host = b"127.0.0.1";
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&target_addr.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);

        client.write_all(b"pong").await.unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"pong");

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        target_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_access_log_records_successful_tunnel_with_bytes() {
        let (access_log, mut rx) = AccessLogger::for_test();
        let (target_addr, target_task) = start_echo_server().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_socks5(
                server,
                &Credentials::default(),
                "hop-socks5",
                "socks5",
                Some(&access_log),
                &crate::stats::TrafficStats::new(),
                test_peer(),
            )
            .await
        });
        authenticate_socks5(&mut client).await;

        let host = b"127.0.0.1";
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&target_addr.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);

        client.write_all(b"pong-pong").await.unwrap();
        let mut echoed = [0u8; 9];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"pong-pong");

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        target_task.await.unwrap();

        let record = rx.try_recv().expect("expected one access log record");
        assert_eq!(record.protocol, "socks5");
        assert_eq!(record.username.as_deref(), Some(DEFAULT_USERNAME));
        assert_eq!(record.decision.as_deref(), Some("direct"));
        assert_eq!(record.client_addr.as_deref(), Some("203.0.113.30:33333"));
        assert!(record.bytes_up >= 9);
        assert!(record.bytes_down >= 9);
    }

    #[tokio::test]
    async fn socks5_active_connection_gauge_reflects_open_tunnel_and_clears_on_close() {
        let (access_log, mut rx) = AccessLogger::for_test();
        let stats = TrafficStats::new();
        let (target_addr, target_task) = start_echo_server().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let gauge_log = access_log.clone();
        let task_stats = stats.clone();
        let task = tokio::spawn(async move {
            serve_socks5(
                server,
                &Credentials::default(),
                "hop-socks5",
                "socks5",
                Some(&gauge_log),
                &task_stats,
                test_peer(),
            )
            .await
        });
        authenticate_socks5(&mut client).await;

        let host = b"127.0.0.1";
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&target_addr.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);

        // Tunnel is open end-to-end: the listener's and egress's active
        // gauges reflect the one in-flight connection.
        let active = |rows: Vec<crate::stats::StatsRow>, name: &str| {
            rows.into_iter().find(|r| r.name == name).map(|r| r.active)
        };
        assert_eq!(active(stats.listener_rows(), "hop-socks5"), Some(1));
        assert_eq!(active(stats.egress_rows(), "direct"), Some(1));

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        target_task.await.unwrap();

        // Connection fully closed: gauge guards dropped, back to zero.
        assert_eq!(active(stats.listener_rows(), "hop-socks5"), Some(0));
        assert_eq!(active(stats.egress_rows(), "direct"), Some(0));
        let record = rx.try_recv().expect("expected one access log record");
        assert_eq!(record.result, "ok");
    }

    async fn authenticate_socks5(client: &mut tokio::io::DuplexStream) {
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);
        let mut auth = vec![0x01, DEFAULT_USERNAME.len() as u8];
        auth.extend_from_slice(DEFAULT_USERNAME.as_bytes());
        auth.push(DEFAULT_PASSWORD.len() as u8);
        auth.extend_from_slice(DEFAULT_PASSWORD.as_bytes());
        client.write_all(&auth).await.unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0x01, 0x00]);
    }

    fn auth_header() -> String {
        base64::engine::general_purpose::STANDARD
            .encode(format!("{DEFAULT_USERNAME}:{DEFAULT_PASSWORD}"))
    }

    fn test_peer() -> SocketAddr {
        "203.0.113.30:33333".parse().unwrap()
    }

    async fn read_response_head(client: &mut tokio::io::DuplexStream) -> String {
        let head = read_http_head(client, 8192).await.unwrap();
        String::from_utf8_lossy(&head).to_string()
    }

    async fn start_echo_server() -> (std::net::SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                socket.write_all(&buf[..n]).await.unwrap();
            }
        });
        (addr, task)
    }
}
