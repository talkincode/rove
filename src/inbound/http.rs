//! HTTP/HTTPS forward proxy: CONNECT tunnelling for HTTPS plus authenticated
//! absolute-form forwarding for plaintext HTTP requests.

use super::Ctx;
use crate::config::SniffMode;
use crate::error::ProxyError;
use crate::io::{copy_throttled, splice, IoStream, PrefixedIo, RateLimiter, SpliceStats};
use crate::model::Decision;
use crate::outbound;
use crate::outbound::decision_label as decision_name;
use crate::sniff::{capture_prefix, SniffObservation, SniffingIo};
use crate::trace::{TraceCandidate, TraceResult, TrafficIdentity};
use crate::util::{read_http_head_with_remainder, split_host_port};
use base64::Engine as _;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;
use url::{Host, Url};

pub async fn serve<S: IoStream>(
    mut stream: S,
    ctx: Arc<Ctx>,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let _connection_guard = ctx.stats.track_listener(&ctx.listener);
    let started = Instant::now();
    let (head, remainder) = read_http_head_with_remainder(&mut stream, 16 * 1024).await?;
    let request = match ParsedRequest::parse(&head) {
        Ok(request) => request,
        Err(e) => {
            respond(&mut stream, e.status, "").await?;
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    failure_stage: Some("parse"),
                    message: Some(e.message),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };
    if let Some(e) = request.validate_remainder(remainder.len()) {
        respond(&mut stream, e.status, "").await?;
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                failure_stage: Some("parse"),
                message: Some(e.message),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }

    let (user, pass) = match request
        .proxy_authorization
        .as_deref()
        .and_then(decode_basic)
    {
        Some(c) => c,
        None => {
            respond(
                &mut stream,
                "407 Proxy Authentication Required",
                "Proxy-Authenticate: Basic realm=\"rove\"\r\n",
            )
            .await?;
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    target_host: Some(request.host.clone()),
                    target_port: Some(request.port),
                    failure_stage: Some("auth"),
                    message: Some("proxy authorization missing"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };

    let auth = match ctx.engine.authenticate(&user, &pass) {
        Ok(a) => a,
        Err(ProxyError::Expired) => {
            respond(&mut stream, "403 Forbidden", "").await?;
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(user),
                    target_host: Some(request.host.clone()),
                    target_port: Some(request.port),
                    failure_stage: Some("auth"),
                    message: Some("user expired"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
        Err(_) => {
            respond(
                &mut stream,
                "407 Proxy Authentication Required",
                "Proxy-Authenticate: Basic realm=\"rove\"\r\n",
            )
            .await?;
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(user),
                    target_host: Some(request.host.clone()),
                    target_port: Some(request.port),
                    failure_stage: Some("auth"),
                    message: Some("authentication failed"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };

    let host = request.host.clone();
    let port = request.port;
    let resolved = ctx.engine.decide_with_sniff(&user, &host, None);
    let decision_name = decision_name(&resolved.decision);
    // Snapshot the routing attribution before the decision is consumed by the
    // dial: every exit path below still has to say which rule decided.
    let attribution = resolved.attribution();
    if let Decision::Block = resolved.decision {
        debug!(user = %user, target = %host, "blocked by policy");
        respond(&mut stream, "403 Forbidden", "").await?;
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                username: Some(user),
                target_host: Some(host),
                target_port: Some(port),
                decision: Some(decision_name),
                policy: Some(attribution.clone()),
                failure_stage: Some("policy"),
                message: Some("blocked by policy"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }

    let connection_permit = match ctx.engine.acquire_connection(&user, auth.max_connections) {
        Ok(permit) => permit,
        Err(ProxyError::ConnectionLimitExceeded { current, max }) => {
            debug!(user = %user, current, max, "connection limit exceeded");
            respond(&mut stream, "429 Too Many Requests", "").await?;
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(user),
                    target_host: Some(host),
                    target_port: Some(port),
                    decision: Some(decision_name),
                    failure_stage: Some("limit"),
                    message: Some("connection limit exceeded"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    let route_connect = ctx.sniff.enabled
        && ctx.sniff.mode == SniffMode::Route
        && matches!(request.target, RequestTarget::Connect);
    if route_connect {
        return tunnel_connect_route(
            stream,
            ctx,
            peer,
            started,
            user,
            host,
            port,
            remainder,
            auth.up_rate,
            auth.down_rate,
            connection_permit,
            resolved,
            decision_name,
        )
        .await;
    }

    let (outbound, egress) =
        match outbound::connect(resolved.decision, &host, port, &ctx.egress).await {
            Ok(established) => established,
            Err(e) => {
                debug!(user = %user, target = %host, error = %e, "upstream connect failed");
                // The status stays a generic 502 (a proxy client only needs "the
                // gateway could not reach the target"), but the access log keeps
                // the stable, greppable stage so ops can tell a reverse_lookup
                // miss apart from a hop_connect failure, a plain outbound dial or
                // an exhausted failover chain.
                let stage = e.failure_stage();
                respond(&mut stream, "502 Bad Gateway", "").await?;
                report_trace(
                    &ctx,
                    started,
                    peer,
                    TraceFields {
                        username: Some(user),
                        target_host: Some(host),
                        target_port: Some(port),
                        decision: Some(decision_name),
                        attempts: e.chain_attempts(),
                        failure_stage: Some(stage),
                        message: Some("upstream connect failed"),
                        ..TraceFields::default()
                    },
                )
                .await;
                return Ok(());
            }
        };

    // The egress dimension counts *established* tunnels: taken only after
    // the outbound connect succeeded, keyed by the concrete egress
    // ("direct" / "upstream:<addr>" / "reverse:<hop>").
    let _egress_guard = ctx.stats.track_egress(&egress.label);
    debug!(user = %user, listener = %ctx.listener, target = %format!("{host}:{port}"), egress = %egress.label, "proxy connection established");
    let ParsedRequest {
        method,
        version,
        headers,
        target,
        body,
        connection_tokens,
        ..
    } = request;
    let (splice_result, sniff_observation) = match target {
        RequestTarget::Connect => {
            tunnel_connect(
                stream,
                outbound,
                remainder,
                auth.up_rate,
                auth.down_rate,
                &ctx.sniff,
            )
            .await
        }
        RequestTarget::Forward(forward) => (
            forward_http(
                stream,
                outbound,
                &method,
                &version,
                &headers,
                &connection_tokens,
                &forward,
                body,
                remainder,
                auth.up_rate,
                auth.down_rate,
            )
            .await,
            None,
        ),
    };
    drop(connection_permit);
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
    report_trace(
        &ctx,
        started,
        peer,
        TraceFields {
            username: Some(user),
            target_host: Some(host),
            target_port: Some(port),
            decision: Some(decision_name),
            egress: egress.chain_id.is_some().then(|| egress.label.clone()),
            chain_member: egress.member_id.clone(),
            attempts: egress.chain_id.is_some().then_some(egress.attempts),
            result,
            sniff: sniff_observation,
            policy: Some(attribution.clone()),
            failure_stage: stage,
            message,
            bytes_up,
            bytes_down,
        },
    )
    .await;
    splice_result?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct RequestError {
    status: &'static str,
    message: &'static str,
}

#[derive(Debug, Clone)]
struct Header {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
struct ParsedRequest {
    method: String,
    version: String,
    headers: Vec<Header>,
    proxy_authorization: Option<String>,
    host: String,
    port: u16,
    target: RequestTarget,
    body: RequestBody,
    connection_tokens: Vec<String>,
}

#[derive(Debug, Clone)]
enum RequestTarget {
    Connect,
    Forward(ForwardTarget),
}

#[derive(Debug, Clone)]
struct ForwardTarget {
    origin_form: String,
    authority: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestBody {
    None,
    Fixed(u64),
    Chunked,
}

impl ParsedRequest {
    fn parse(head: &[u8]) -> Result<Self, RequestError> {
        let text = std::str::from_utf8(head).map_err(|_| RequestError {
            status: "400 Bad Request",
            message: "request header is not valid UTF-8",
        })?;
        let text = text.strip_suffix("\r\n\r\n").unwrap_or(text);
        let mut lines = text.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().unwrap_or("");
        let raw_target = request_parts.next().unwrap_or("");
        let version = request_parts.next().unwrap_or("");
        if method.is_empty()
            || raw_target.is_empty()
            || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
            || request_parts.next().is_some()
        {
            return Err(RequestError {
                status: "400 Bad Request",
                message: "malformed request line",
            });
        }

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if line.starts_with([' ', '\t']) {
                return Err(RequestError {
                    status: "400 Bad Request",
                    message: "obsolete folded header is not supported",
                });
            }
            let Some((name, value)) = line.split_once(':') else {
                return Err(RequestError {
                    status: "400 Bad Request",
                    message: "malformed request header",
                });
            };
            if !valid_header_name(name) {
                return Err(RequestError {
                    status: "400 Bad Request",
                    message: "malformed request header name",
                });
            }
            let value = value.trim();
            if value.bytes().any(
                |b| matches!(b, b'\r' | b'\n' | 0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f),
            ) {
                return Err(RequestError {
                    status: "400 Bad Request",
                    message: "malformed request header value",
                });
            }
            headers.push(Header {
                name: name.to_string(),
                value: value.to_string(),
            });
        }

        let proxy_auth_values: Vec<_> = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("proxy-authorization"))
            .map(|h| h.value.clone())
            .collect();
        if proxy_auth_values.len() > 1 {
            return Err(RequestError {
                status: "400 Bad Request",
                message: "multiple proxy authorization headers",
            });
        }
        let proxy_authorization = proxy_auth_values.into_iter().next();

        let connection_tokens: Vec<String> = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("connection"))
            .flat_map(|h| h.value.split(','))
            .map(|token| token.trim().to_ascii_lowercase())
            .filter(|token| !token.is_empty())
            .collect();
        if headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("upgrade"))
            || connection_tokens.iter().any(|token| token == "upgrade")
        {
            return Err(RequestError {
                status: "501 Not Implemented",
                message: "HTTP upgrade requires a CONNECT tunnel",
            });
        }
        if connection_tokens
            .iter()
            .any(|token| matches!(token.as_str(), "content-length" | "transfer-encoding"))
        {
            return Err(RequestError {
                status: "400 Bad Request",
                message: "ambiguous request framing",
            });
        }

        let body = parse_request_body(method, &headers)?;
        let (host, port, target) = if method.eq_ignore_ascii_case("CONNECT") {
            if body != RequestBody::None {
                return Err(RequestError {
                    status: "400 Bad Request",
                    message: "CONNECT request must not carry a body",
                });
            }
            let (host, port) = split_host_port(raw_target).ok_or(RequestError {
                status: "400 Bad Request",
                message: "bad connect target",
            })?;
            if host.is_empty() || port == 0 {
                return Err(RequestError {
                    status: "400 Bad Request",
                    message: "bad connect target",
                });
            }
            (host, port, RequestTarget::Connect)
        } else {
            let url = Url::parse(raw_target).map_err(|_| RequestError {
                status: "405 Method Not Allowed",
                message: "non-CONNECT requests require an absolute HTTP URI",
            })?;
            if url.scheme() != "http"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(RequestError {
                    status: "400 Bad Request",
                    message: "unsupported absolute request target",
                });
            }
            let host = match url.host() {
                Some(Host::Domain(host)) => host.to_string(),
                Some(Host::Ipv4(ip)) => ip.to_string(),
                Some(Host::Ipv6(ip)) => ip.to_string(),
                None => {
                    return Err(RequestError {
                        status: "400 Bad Request",
                        message: "absolute request target has no host",
                    })
                }
            };
            let port = url.port_or_known_default().ok_or(RequestError {
                status: "400 Bad Request",
                message: "absolute request target has no port",
            })?;
            if port == 0 {
                return Err(RequestError {
                    status: "400 Bad Request",
                    message: "absolute request target has invalid port",
                });
            }
            let mut origin_form = url.path().to_string();
            if origin_form.is_empty() {
                origin_form.push('/');
            }
            if let Some(query) = url.query() {
                origin_form.push('?');
                origin_form.push_str(query);
            }
            let authority = format_authority(&host, port);
            (
                host,
                port,
                RequestTarget::Forward(ForwardTarget {
                    origin_form,
                    authority,
                }),
            )
        };

        Ok(ParsedRequest {
            method: method.to_string(),
            version: version.to_string(),
            headers,
            proxy_authorization,
            host,
            port,
            target,
            body,
            connection_tokens,
        })
    }

    fn validate_remainder(&self, remainder_len: usize) -> Option<RequestError> {
        if !matches!(self.target, RequestTarget::Forward(_)) {
            return None;
        }
        match self.body {
            RequestBody::None if remainder_len > 0 => Some(RequestError {
                status: "400 Bad Request",
                message: "request bytes exceed declared body",
            }),
            RequestBody::Fixed(length) if remainder_len as u64 > length => Some(RequestError {
                status: "400 Bad Request",
                message: "request bytes exceed content length",
            }),
            _ => None,
        }
    }
}

fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn parse_request_body(method: &str, headers: &[Header]) -> Result<RequestBody, RequestError> {
    let content_lengths: Vec<_> = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
        .map(|h| h.value.trim())
        .collect();
    let transfer_encodings: Vec<_> = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|h| h.value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();

    if !content_lengths.is_empty() && !transfer_encodings.is_empty() {
        return Err(RequestError {
            status: "400 Bad Request",
            message: "ambiguous request body framing",
        });
    }
    if !transfer_encodings.is_empty() {
        if transfer_encodings.last().map(String::as_str) != Some("chunked") {
            return Err(RequestError {
                status: "501 Not Implemented",
                message: "unsupported transfer encoding",
            });
        }
        return Ok(RequestBody::Chunked);
    }
    if let Some(first) = content_lengths.first() {
        if content_lengths.iter().any(|value| value != first) {
            return Err(RequestError {
                status: "400 Bad Request",
                message: "conflicting content lengths",
            });
        }
        let length = first.parse::<u64>().map_err(|_| RequestError {
            status: "400 Bad Request",
            message: "invalid content length",
        })?;
        return Ok(if length == 0 {
            RequestBody::None
        } else {
            RequestBody::Fixed(length)
        });
    }
    if matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH"
    ) {
        return Err(RequestError {
            status: "411 Length Required",
            message: "request body length is required",
        });
    }
    Ok(RequestBody::None)
}

fn format_authority(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == 80 {
        host
    } else {
        format!("{host}:{port}")
    }
}

#[allow(clippy::too_many_arguments)]
async fn tunnel_connect_route<S: IoStream>(
    mut stream: S,
    ctx: Arc<Ctx>,
    peer: SocketAddr,
    started: Instant,
    user: String,
    host: String,
    port: u16,
    remainder: Vec<u8>,
    up_rate: u64,
    down_rate: u64,
    connection_permit: crate::engine::ConnectionPermit,
    mut resolved: crate::model::ResolvedDecision,
    mut decision_name: String,
) -> anyhow::Result<()> {
    // Snapshot the routing attribution before the decision is consumed by the
    // dial: every exit path below still has to say which rule decided.
    let mut attribution = resolved.attribution();
    if let Err(error) = stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
    {
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                username: Some(user),
                target_host: Some(host),
                target_port: Some(port),
                decision: Some(decision_name),
                policy: Some(attribution.clone()),
                failure_stage: Some("splice"),
                message: Some("tunnel io failed"),
                ..TraceFields::default()
            },
        )
        .await;
        return Err(error.into());
    }

    let mut stream = PrefixedIo::new(remainder, stream);
    let captured = match capture_prefix(&mut stream, ctx.sniff.max_bytes, ctx.sniff.timeout()).await
    {
        Ok(captured) => captured,
        Err(error) => {
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(user),
                    target_host: Some(host),
                    target_port: Some(port),
                    decision: Some(decision_name),
                    policy: Some(attribution.clone()),
                    failure_stage: Some("sniff_read"),
                    message: Some("route sniff read failed"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Err(error.into());
        }
    };
    resolved = ctx
        .engine
        .decide_with_sniff(&user, &host, captured.observation.host.as_deref());
    decision_name = crate::outbound::decision_label(&resolved.decision);
    attribution = resolved.attribution();
    let sniff_observation = Some(captured.observation);
    if let Decision::Block = resolved.decision {
        debug!(
            user = %user,
            target = %host,
            effective_policy_host = %resolved.effective_policy_host,
            "http connect blocked by sniffed policy"
        );
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                username: Some(user),
                target_host: Some(host),
                target_port: Some(port),
                decision: Some(decision_name),
                sniff: sniff_observation,
                policy: Some(attribution.clone()),
                failure_stage: Some("policy"),
                message: Some("blocked by requested or sniffed target policy"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }

    let (outbound, egress) =
        match outbound::connect(resolved.decision, &host, port, &ctx.egress).await {
            Ok(established) => established,
            Err(e) => {
                debug!(user = %user, target = %host, error = %e, "upstream connect failed");
                report_trace(
                    &ctx,
                    started,
                    peer,
                    TraceFields {
                        username: Some(user),
                        target_host: Some(host),
                        target_port: Some(port),
                        decision: Some(decision_name),
                        sniff: sniff_observation,
                        policy: Some(attribution.clone()),
                        attempts: e.chain_attempts(),
                        failure_stage: Some(e.failure_stage()),
                        message: Some("upstream connect failed"),
                        ..TraceFields::default()
                    },
                )
                .await;
                return Ok(());
            }
        };
    let _egress_guard = ctx.stats.track_egress(&egress.label);
    debug!(
        user = %user,
        listener = %ctx.listener,
        target = %format!("{host}:{port}"),
        egress = %egress.label,
        "proxy connection established"
    );
    let stream = PrefixedIo::new(captured.bytes, stream);
    let splice_result = splice(stream, outbound, up_rate, down_rate).await;
    drop(connection_permit);
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
    report_trace(
        &ctx,
        started,
        peer,
        TraceFields {
            username: Some(user),
            target_host: Some(host),
            target_port: Some(port),
            decision: Some(decision_name),
            egress: egress.chain_id.is_some().then(|| egress.label.clone()),
            chain_member: egress.member_id.clone(),
            attempts: egress.chain_id.is_some().then_some(egress.attempts),
            result,
            sniff: sniff_observation,
            policy: Some(attribution.clone()),
            failure_stage: stage,
            message,
            bytes_up,
            bytes_down,
        },
    )
    .await;
    splice_result?;
    Ok(())
}

async fn tunnel_connect<S: IoStream>(
    mut stream: S,
    outbound: Box<dyn IoStream>,
    remainder: Vec<u8>,
    up_rate: u64,
    down_rate: u64,
    sniff: &crate::config::SniffConfig,
) -> (io::Result<SpliceStats>, Option<SniffObservation>) {
    if let Err(error) = stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
    {
        return (Err(error), None);
    }
    let stream = PrefixedIo::new(remainder, stream);
    if sniff.enabled {
        let (stream, handle) = SniffingIo::new(stream, sniff.max_bytes, sniff.timeout());
        let result = splice(stream, outbound, up_rate, down_rate).await;
        (result, Some(handle.observation()))
    } else {
        (splice(stream, outbound, up_rate, down_rate).await, None)
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_http<S: IoStream>(
    stream: S,
    mut outbound: Box<dyn IoStream>,
    method: &str,
    version: &str,
    headers: &[Header],
    connection_tokens: &[String],
    target: &ForwardTarget,
    body: RequestBody,
    remainder: Vec<u8>,
    up_rate: u64,
    down_rate: u64,
) -> io::Result<SpliceStats> {
    let forwarded_head = build_forward_head(method, version, headers, connection_tokens, target);
    outbound.write_all(&forwarded_head).await?;
    let head_bytes = forwarded_head.len() as u64;

    let (client_read, client_write) = tokio::io::split(stream);
    let (server_read, mut server_write) = tokio::io::split(outbound);
    let upload = async move {
        let mut reader = PrefixedIo::new(remainder, client_read);
        let mut limiter = RateLimiter::new(up_rate);
        let body_bytes =
            copy_request_body(&mut reader, &mut server_write, body, &mut limiter).await?;
        let _ = server_write.shutdown().await;
        Ok::<u64, io::Error>(head_bytes.saturating_add(body_bytes))
    };
    let download = copy_throttled(server_read, client_write, down_rate);
    let (bytes_up, bytes_down) = tokio::join!(upload, download);
    Ok(SpliceStats {
        bytes_up: bytes_up?,
        bytes_down: bytes_down?,
    })
}

fn build_forward_head(
    method: &str,
    version: &str,
    headers: &[Header],
    connection_tokens: &[String],
    target: &ForwardTarget,
) -> Vec<u8> {
    let mut head = format!(
        "{method} {} {version}\r\nHost: {}\r\n",
        target.origin_form, target.authority
    );
    for header in headers {
        let lower = header.name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "proxy-authorization"
                | "proxy-connection"
                | "connection"
                | "keep-alive"
                | "upgrade"
        ) || connection_tokens.iter().any(|token| token == &lower)
        {
            continue;
        }
        head.push_str(&header.name);
        head.push_str(": ");
        head.push_str(&header.value);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    head.into_bytes()
}

async fn copy_request_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    body: RequestBody,
    limiter: &mut RateLimiter,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        RequestBody::None => Ok(0),
        RequestBody::Fixed(length) => copy_exact_body(reader, writer, length, limiter).await,
        RequestBody::Chunked => copy_chunked_body(reader, writer, limiter).await,
    }
}

async fn copy_exact_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
    limiter: &mut RateLimiter,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let total = remaining;
    let mut buf = vec![0u8; 32 * 1024];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());
        let n = reader.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request body ended before content length",
            ));
        }
        limiter.write_all(writer, &buf[..n]).await?;
        remaining -= n as u64;
    }
    Ok(total)
}

async fn copy_chunked_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    limiter: &mut RateLimiter,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        let line = read_crlf_line(reader).await?;
        let size_text = std::str::from_utf8(
            line.strip_suffix(b"\r\n")
                .unwrap_or(line.as_slice())
                .split(|b| *b == b';')
                .next()
                .unwrap_or_default(),
        )
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?
        .trim();
        let size = u64::from_str_radix(size_text, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        limiter.write_all(writer, &line).await?;
        total = total.saturating_add(line.len() as u64);

        if size == 0 {
            loop {
                let trailer = read_crlf_line(reader).await?;
                limiter.write_all(writer, &trailer).await?;
                total = total.saturating_add(trailer.len() as u64);
                if trailer == b"\r\n" {
                    return Ok(total);
                }
            }
        }

        total = total.saturating_add(copy_exact_body(reader, writer, size, limiter).await?);
        let mut terminator = [0u8; 2];
        reader.read_exact(&mut terminator).await?;
        if terminator != *b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk data missing CRLF",
            ));
        }
        limiter.write_all(writer, &terminator).await?;
        total = total.saturating_add(2);
    }
}

async fn read_crlf_line<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    const MAX_CHUNK_LINE: usize = 8 * 1024;
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.len() >= MAX_CHUNK_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunk line too large",
            ));
        }
    }
}

async fn respond<S: IoStream>(stream: &mut S, status: &str, extra: &str) -> std::io::Result<()> {
    let msg = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(msg.as_bytes()).await
}

fn decode_basic(value: &str) -> Option<(String, String)> {
    let b64 = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let s = String::from_utf8(raw).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

struct TraceFields<'a> {
    username: Option<String>,
    target_host: Option<String>,
    target_port: Option<u16>,
    decision: Option<String>,
    /// Physical egress when the decision was a chain (winning member outlet).
    egress: Option<String>,
    chain_member: Option<String>,
    attempts: Option<u32>,
    sniff: Option<SniffObservation>,
    /// Routing attribution; `None` when the connection failed before routing.
    policy: Option<crate::model::PolicyAttribution>,
    result: TraceResult,
    failure_stage: Option<&'a str>,
    message: Option<&'a str>,
    bytes_up: u64,
    bytes_down: u64,
}

impl Default for TraceFields<'_> {
    fn default() -> Self {
        TraceFields {
            username: None,
            target_host: None,
            target_port: None,
            decision: None,
            egress: None,
            chain_member: None,
            attempts: None,
            sniff: None,
            policy: None,
            result: TraceResult::Error,
            failure_stage: None,
            message: None,
            bytes_up: 0,
            bytes_down: 0,
        }
    }
}

async fn report_trace(ctx: &Arc<Ctx>, started: Instant, peer: SocketAddr, fields: TraceFields<'_>) {
    // Traffic counters are always on (they feed SNMP even when tracing,
    // diagnostics and the access log are all disabled). Blocked decisions
    // never open an egress row: nothing left the node. Chain decisions count
    // bytes under the physical member outlet, matching `track_egress`.
    ctx.stats
        .record_listener_bytes(&ctx.listener, fields.bytes_up, fields.bytes_down);
    if let Some(observation) = &fields.sniff {
        ctx.stats.record_sniff(&ctx.listener, observation.outcome);
    }
    if let Some(decision) = fields.egress.as_deref().or(fields.decision.as_deref()) {
        if decision != "block" {
            ctx.stats
                .record_egress_bytes(decision, fields.bytes_up, fields.bytes_down);
        }
    }
    if ctx.tracer.is_none() && ctx.diagnostics.is_none() && ctx.access_log.is_none() {
        return;
    }
    let traffic = fields
        .target_host
        .as_ref()
        .zip(fields.target_port)
        .map(|(host, port)| {
            let mut identity = TrafficIdentity::new(host.clone(), port);
            if let Some(policy) = fields.policy.clone() {
                identity = identity.with_policy(policy);
            }
            match fields.sniff.clone() {
                Some(observation) => identity.with_observation(observation),
                None => identity,
            }
        });
    let candidate = TraceCandidate {
        listener: ctx.listener.clone(),
        protocol: "http".to_string(),
        client_addr: Some(peer.to_string()),
        username: fields.username,
        target_host: fields.target_host,
        target_port: fields.target_port,
        traffic,
        decision: fields.decision,
        egress: fields.egress,
        chain_member: fields.chain_member,
        attempts: fields.attempts,
        result: fields.result,
        failure_stage: fields.failure_stage.map(str::to_string),
        message: fields.message.map(str::to_string),
        snapshot_version: ctx.engine.version(),
        duration_ms: started.elapsed().as_millis(),
    };
    // Diagnostics is the non-blocking, multi-session fan-out; the one-shot probe
    // tracer stays a separate, backward-compatible consumer of the same candidate.
    if let Some(diagnostics) = &ctx.diagnostics {
        diagnostics.record(&candidate);
    }
    if let Some(access_log) = &ctx.access_log {
        access_log.record(&candidate, fields.bytes_up, fields.bytes_down);
    }
    if let Some(tracer) = &ctx.tracer {
        tracer.finish(candidate).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::model::test_support::PolicySpec;
    use crate::model::{RawSnapshot, RawUser, Snapshot};
    use crate::util::read_http_head;
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// Fixed source address for tests that go through an in-memory
    /// `tokio::io::duplex` stream instead of a real TCP accept loop, so
    /// there is no real peer `SocketAddr` to use.
    fn test_peer() -> SocketAddr {
        "203.0.113.10:51234".parse().unwrap()
    }

    #[test]
    fn decode_basic_accepts_case_insensitive_basic_scheme() {
        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");

        assert_eq!(
            decode_basic(&format!("Basic {token}")).unwrap(),
            ("alice".to_string(), "secret".to_string())
        );
        assert_eq!(
            decode_basic(&format!("basic {token}")).unwrap(),
            ("alice".to_string(), "secret".to_string())
        );
        assert!(decode_basic("Bearer nope").is_none());
        assert!(decode_basic("Basic not-base64").is_none());
    }

    #[test]
    fn decision_name_embeds_upstream_address_but_never_credentials() {
        use crate::model::{Upstream, UpstreamKind};

        assert_eq!(decision_name(&Decision::Direct), "direct");
        assert_eq!(decision_name(&Decision::Block), "block");

        let via = Decision::Via(Upstream {
            kind: UpstreamKind::Http,
            addr: "10.0.0.5:1080".to_string(),
            username: Some("hop-user".to_string()),
            password: Some("hop-secret".to_string()),
            tls: false,
            skip_cert_verify: false,
        });
        let name = decision_name(&via);
        assert_eq!(name, "upstream:10.0.0.5:1080");
        assert!(!name.contains("hop-user"));
        assert!(!name.contains("hop-secret"));
    }

    #[tokio::test]
    async fn chunked_body_copy_stops_before_a_pipelined_request() {
        let input =
            b"4\r\ntest\r\n3\r\n123\r\n0\r\nX-Trailer: done\r\n\r\nGET /next HTTP/1.1\r\n\r\n";
        let mut reader = &input[..];
        let (mut output, mut writer) = tokio::io::duplex(1024);
        let mut limiter = RateLimiter::new(0);

        let copied = copy_chunked_body(&mut reader, &mut writer, &mut limiter)
            .await
            .unwrap();
        drop(writer);
        let mut forwarded = Vec::new();
        output.read_to_end(&mut forwarded).await.unwrap();

        let expected = b"4\r\ntest\r\n3\r\n123\r\n0\r\nX-Trailer: done\r\n\r\n";
        assert_eq!(copied, expected.len() as u64);
        assert_eq!(forwarded, expected);
        assert_eq!(reader, b"GET /next HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn absolute_ipv6_target_uses_bare_policy_host_and_single_bracket_authority() {
        let request = ParsedRequest::parse(
            b"GET http://[::1]:8080/path HTTP/1.1\r\nProxy-Authorization: Basic test\r\n\r\n",
        )
        .unwrap();

        assert_eq!(request.host, "::1");
        assert_eq!(request.port, 8080);
        let RequestTarget::Forward(target) = &request.target else {
            panic!("expected forward target");
        };
        assert_eq!(target.authority, "[::1]:8080");
        let head = String::from_utf8(build_forward_head(
            &request.method,
            &request.version,
            &request.headers,
            &request.connection_tokens,
            target,
        ))
        .unwrap();
        assert!(head.contains("Host: [::1]:8080\r\n"));
        assert!(!head.contains("[[::1]]"));
    }

    #[test]
    fn rejects_bare_cr_or_lf_inside_header_values() {
        for request in [
            b"GET http://example.com/ HTTP/1.1\r\nX-Test: safe\nX-Evil: injected\r\n\r\n"
                .as_slice(),
            b"GET http://example.com/ HTTP/1.1\r\nX-Test: safe\rX-Evil: injected\r\n\r\n"
                .as_slice(),
        ] {
            let err = ParsedRequest::parse(request).unwrap_err();
            assert_eq!(err.status, "400 Bad Request");
            assert_eq!(err.message, "malformed request header value");
        }
    }

    #[tokio::test]
    async fn rejects_method_missing_auth_bad_auth_and_bad_target() {
        let response = run_request(
            b"GET / HTTP/1.1\r\n\r\n",
            engine_with_user("secret", "2099-12-31"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 405"));

        let response = run_request(
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
            engine_with_user("secret", "2099-12-31"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 407"));

        let token = base64::engine::general_purpose::STANDARD.encode("alice:wrong");
        let response = run_request(
            format!(
                "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
            )
            .as_bytes(),
            engine_with_user("secret", "2099-12-31"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 407"));

        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let response = run_request(
            format!("CONNECT missing-port HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n")
                .as_bytes(),
            engine_with_user("secret", "2099-12-31"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 400"));
    }

    #[tokio::test]
    async fn rejects_expired_users_before_policy() {
        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let response = run_request(
            format!(
                "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
            )
            .as_bytes(),
            engine_with_user("secret", "2000-01-01"),
        )
        .await;

        assert!(response.starts_with("HTTP/1.1 403"));
    }

    #[tokio::test]
    async fn access_log_records_completed_connections_independent_of_tracer_and_diagnostics() {
        let (logger, mut rx) = crate::access_log::AccessLogger::for_test();
        let (mut client, server) = tokio::io::duplex(4096);
        let ctx = Arc::new(Ctx {
            engine: engine_with_user("secret", "2099-12-31"),
            listener: "test-http".to_string(),
            sniff: crate::config::SniffConfig::default(),
            tracer: None,
            diagnostics: None,
            access_log: Some(logger),
            stats: crate::stats::TrafficStats::new(),
            egress: crate::outbound::EgressContext::default(),
        });
        let task = tokio::spawn(serve(server, ctx, test_peer()));
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let _ = read_http_head(&mut client, 8192).await.unwrap();
        task.await.unwrap().unwrap();

        let record = rx.try_recv().expect("access log record enqueued");
        assert_eq!(record.node_id, "test-node");
        assert_eq!(record.listener, "test-http");
        assert_eq!(record.protocol, "http");
        assert_eq!(record.client_addr.as_deref(), Some("203.0.113.10:51234"));
        assert_eq!(record.failure_stage.as_deref(), Some("auth"));
        assert_eq!(record.bytes_up, 0);
        assert_eq!(record.bytes_down, 0);
    }

    #[tokio::test]
    async fn active_connection_gauge_reflects_open_tunnel_and_clears_on_close() {
        let (logger, mut rx) = crate::access_log::AccessLogger::for_test();
        let stats = crate::stats::TrafficStats::new();
        let (target_addr, target_task) = start_echo_server().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let ctx = Arc::new(Ctx {
            engine: engine_with_user("secret", "2099-12-31"),
            listener: "test-http".to_string(),
            sniff: crate::config::SniffConfig::default(),
            tracer: None,
            diagnostics: None,
            access_log: Some(logger.clone()),
            stats: stats.clone(),
            egress: crate::outbound::EgressContext::default(),
        });
        let task = tokio::spawn(serve(server, ctx, test_peer()));

        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        client
            .write_all(
                format!(
                    "CONNECT {target_addr} HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut client, 8192).await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

        // Tunnel is open end-to-end: the listener's and egress's active
        // gauges reflect the one in-flight connection, fed by the
        // `TrafficStats` guards held for the lifetime of `serve()`.
        let row = |rows: Vec<crate::stats::StatsRow>, name: &str| {
            rows.into_iter().find(|r| r.name == name)
        };
        assert_eq!(
            row(stats.listener_rows(), "test-http").unwrap().active,
            1,
            "listener gauge while tunnel open"
        );
        assert_eq!(
            row(stats.egress_rows(), "direct").unwrap().active,
            1,
            "egress gauge while tunnel open"
        );

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        target_task.await.unwrap();

        // Connection fully closed: gauge guards dropped, back to zero, and
        // the splice byte counts were folded into both dimensions.
        let listener_row = row(stats.listener_rows(), "test-http").unwrap();
        assert_eq!(listener_row.active, 0);
        let egress_row = row(stats.egress_rows(), "direct").unwrap();
        assert_eq!(egress_row.active, 0);
        assert_eq!(listener_row.bytes_up_total, egress_row.bytes_up_total);
        assert_eq!(listener_row.bytes_down_total, egress_row.bytes_down_total);
        let record = rx.try_recv().expect("access log record enqueued");
        assert_eq!(record.result, "ok");
        assert_eq!(listener_row.bytes_up_total, record.bytes_up);
        assert_eq!(listener_row.bytes_down_total, record.bytes_down);
    }

    #[tokio::test]
    async fn authenticates_username_and_password_containing_special_characters() {
        // `@` breaks curl's inline `user:pass@host:port` proxy URL syntax
        // client-side, but that's a client URL-parsing concern, not this
        // server's. HTTP Basic auth only ever splits on the *first* `:`
        // (`decode_basic`), and the compiled snapshot looks users up by exact
        // string in a HashMap (`Snapshot::user`) -- neither cares about `@`,
        // and the password may even contain further `:` characters.
        let username = "user@example.com";
        let password = "P@ss:w0rd!";
        let mut users = HashMap::new();
        users.insert(
            username.to_string(),
            RawUser {
                password: password.to_string(),
                expire: Some("2099-12-31".to_string()),
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                policy: "open".to_string(),
                frontends: Default::default(),
            },
        );
        let (routing_policies, egresses) = PolicySpec::default().into_tables("open");
        let engine = Engine::new();
        engine.replace(
            Snapshot::compile(
                RawSnapshot {
                    version: 1,
                    users,
                    routing_policies,
                    egresses,
                    ..Default::default()
                },
                "node-1",
            )
            .unwrap(),
        );

        let (target_addr, target_task) = start_echo_server().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let ctx = Arc::new(Ctx {
            engine,
            listener: "test-http".to_string(),
            sniff: crate::config::SniffConfig::default(),
            tracer: None,
            diagnostics: None,
            access_log: None,
            stats: crate::stats::TrafficStats::new(),
            egress: crate::outbound::EgressContext::default(),
        });
        let task = tokio::spawn(serve(server, ctx, test_peer()));

        let token =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        client
            .write_all(
                format!(
                    "CONNECT {target_addr} HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut client, 8192).await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        target_task.await.unwrap();
    }

    async fn start_echo_server() -> (SocketAddr, JoinHandle<()>) {
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

    /// Minimal HTTP CONNECT upstream: accepts one CONNECT, replies 200 and
    /// echoes the tunnel bytes.
    async fn start_connect_upstream() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let head = read_http_head(&mut socket, 8192).await.unwrap();
            assert!(String::from_utf8_lossy(&head).starts_with("CONNECT "));
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 32];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });
        (addr, task)
    }

    fn engine_with_chain(members: Vec<(&str, u32, &str, String)>) -> Arc<Engine> {
        use crate::model::{RawAction, RawChainMember, RawEgress, RawRoutingPolicy, RawUpstream};
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                policy: "chained".to_string(),
                frontends: Default::default(),
            },
        );
        let routing_policies = HashMap::from([(
            "chained".to_string(),
            RawRoutingPolicy {
                routes: Vec::new(),
                default_action: Some(RawAction::Egress {
                    egress: "jp-pop".to_string(),
                }),
            },
        )]);
        let egresses = HashMap::from([(
            "jp-pop".to_string(),
            RawEgress::Chain {
                members: members
                    .into_iter()
                    .map(|(id, priority, kind, addr)| RawChainMember {
                        id: id.to_string(),
                        priority,
                        backend: RawUpstream {
                            kind: kind.to_string(),
                            addr,
                            username: None,
                            password: None,
                            tls: false,
                            skip_cert_verify: false,
                        },
                    })
                    .collect(),
            },
        )]);
        let engine = Engine::new();
        engine.replace(
            Snapshot::compile(
                RawSnapshot {
                    version: 1,
                    users,
                    routing_policies,
                    egresses,
                    ..Default::default()
                },
                "node-1",
            )
            .unwrap(),
        );
        engine
    }

    /// End-to-end acceptance: the primary member is down, the tunnel must be
    /// established through the backup member and carry bytes.
    #[tokio::test]
    async fn connect_via_chain_fails_over_to_backup_member() {
        // A dead primary: bind + drop => connection refused.
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = l.local_addr().unwrap();
            drop(l);
            addr.to_string()
        };
        let (backup_addr, backup_task) = start_connect_upstream().await;
        let engine = engine_with_chain(vec![
            ("jp-primary", 1, "http", dead),
            ("jp-backup", 2, "http", backup_addr.to_string()),
        ]);

        let (mut client, server) = tokio::io::duplex(4096);
        let ctx = Arc::new(Ctx {
            engine,
            listener: "test-http".to_string(),
            sniff: crate::config::SniffConfig::default(),
            tracer: None,
            diagnostics: None,
            access_log: None,
            stats: crate::stats::TrafficStats::new(),
            egress: crate::outbound::EgressContext::default(),
        });
        let task = tokio::spawn(serve(server, ctx, test_peer()));

        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        client
            .write_all(
                format!(
                    "CONNECT target.example:443 HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let response = read_http_head(&mut client, 8192).await.unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));

        client.write_all(b"failover-ok").await.unwrap();
        let mut echoed = [0u8; 11];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"failover-ok");

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        backup_task.await.unwrap();
    }

    /// End-to-end acceptance: all members down => 502, never a direct dial.
    #[tokio::test]
    async fn connect_via_exhausted_chain_fails_closed_with_502() {
        let dead1 = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a.to_string()
        };
        let dead2 = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            drop(l);
            a.to_string()
        };
        // The "target" is a live local echo server: if fail-closed were
        // violated by an implicit direct fallback, the request would succeed.
        let (target_addr, target_task) = start_echo_server().await;
        let engine = engine_with_chain(vec![("m1", 1, "http", dead1), ("m2", 2, "socks5", dead2)]);

        let token = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let head = run_request(
            format!("CONNECT {target_addr} HTTP/1.1\r\nProxy-Authorization: Basic {token}\r\n\r\n")
                .as_bytes(),
            engine,
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 502"), "got: {head}");
        target_task.abort();
    }

    async fn run_request(bytes: &[u8], engine: Arc<Engine>) -> String {
        let (mut client, server) = tokio::io::duplex(4096);
        let ctx = Arc::new(Ctx {
            engine,
            listener: "test-http".to_string(),
            sniff: crate::config::SniffConfig::default(),
            tracer: None,
            diagnostics: None,
            access_log: None,
            stats: crate::stats::TrafficStats::new(),
            egress: crate::outbound::EgressContext::default(),
        });
        let task = tokio::spawn(serve(server, ctx, test_peer()));
        client.write_all(bytes).await.unwrap();
        let head = read_http_head(&mut client, 8192).await.unwrap();
        task.await.unwrap().unwrap();
        String::from_utf8_lossy(&head).to_string()
    }

    fn engine_with_user(password: &str, expire: &str) -> Arc<Engine> {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: password.to_string(),
                expire: Some(expire.to_string()),
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                policy: "open".to_string(),
                frontends: Default::default(),
            },
        );
        let (routing_policies, egresses) = PolicySpec::default().into_tables("open");
        let engine = Engine::new();
        engine.replace(
            Snapshot::compile(
                RawSnapshot {
                    version: 1,
                    users,
                    routing_policies,
                    egresses,
                    ..Default::default()
                },
                "node-1",
            )
            .unwrap(),
        );
        engine
    }
}
