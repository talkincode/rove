//! Outbound layer: open the connection to the target, either directly or via a
//! secondary (upstream) proxy. Supports `http` and `socks5` upstreams (each
//! optionally over TLS), `reverse` upstreams routed over an authenticated
//! reverse-hop QUIC session, and named failover `chains` (priority-ordered
//! primary/backup candidates tried only during tunnel establishment).

use crate::error::{ProxyError, Result};
use crate::io::IoStream;
use crate::model::{Chain, Decision, Upstream, UpstreamKind};
use crate::reverse::ReverseHopManager;
use crate::subnetra::netstack::NetHandle;
use crate::tls;
use crate::util::{host_of, http_2xx, read_http_head};
use base64::Engine as _;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

/// Upper bound for one chain member establishment attempt. Applies on top of
/// the member's own internal timeouts (TCP dial, reverse `open_timeout`) so a
/// stuck handshake cannot absorb the whole failover budget.
pub const CHAIN_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound for one request's total failover time across all chain
/// members. When the budget runs out remaining members are not tried and the
/// connection fails closed.
pub const CHAIN_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Runtime-owned capabilities that can establish egress outside the ordinary
/// direct and dialed-upstream paths.
#[derive(Clone, Default)]
pub struct EgressContext {
    reverse: Option<Arc<ReverseHopManager>>,
    subnetra: Option<NetHandle>,
}

impl EgressContext {
    pub fn new(reverse: Option<Arc<ReverseHopManager>>, subnetra: Option<NetHandle>) -> Self {
        Self { reverse, subnetra }
    }

    fn reverse(&self) -> Option<&Arc<ReverseHopManager>> {
        self.reverse.as_ref()
    }

    fn subnetra(&self) -> Option<&NetHandle> {
        self.subnetra.as_ref()
    }
}

/// How the connection actually left the node — resolved by `connect` /
/// `connect_udp` after the decision, since a chain decision only picks the
/// candidate set, not the concrete backend.
#[derive(Debug, Clone)]
pub struct EgressInfo {
    /// Safe, credential-free outlet label: `direct`, `upstream:<addr>`,
    /// `reverse:<hop_id>` or `subnetra`. For chains this is the *winning
    /// member's* outlet, so stats keep the physical-egress dimension while
    /// the access-log `decision` keeps the logical `chain:<id>` dimension.
    pub label: String,
    /// Chain id when the decision was a chain.
    pub chain_id: Option<String>,
    /// Winning chain member id.
    pub member_id: Option<String>,
    /// Establishment attempts performed (1 for non-chain decisions).
    pub attempts: u32,
}

impl EgressInfo {
    fn single(label: String) -> Self {
        EgressInfo {
            label,
            chain_id: None,
            member_id: None,
            attempts: 1,
        }
    }
}

/// Safe outlet label for one concrete upstream; never includes credentials.
pub fn egress_label(up: &Upstream) -> String {
    match up.kind {
        UpstreamKind::Reverse => format!("reverse:{}", up.addr),
        UpstreamKind::Subnetra => "subnetra".to_string(),
        _ => format!("upstream:{}", up.addr),
    }
}

/// Category plus, for `Via`, the specific upstream actually selected -- never
/// the upstream's username/password. This is the parity fix for old GOST's
/// `hoplog.node_addr`: knowing "went via an upstream" is not enough to
/// grep-diagnose a hop-node-specific fault, you need to know *which* one.
/// Reverse upstreams render as `reverse:<hop_id>` so a reverse route is
/// distinguishable from a dialed `upstream:<addr>`; chain decisions render as
/// `chain:<chain_id>` (the logical egress — the physical member lands in
/// [`EgressInfo::label`]).
pub fn decision_label(decision: &Decision) -> String {
    match decision {
        Decision::Direct => "direct".to_string(),
        Decision::Via(up) => egress_label(up),
        Decision::ViaChain(chain) => format!("chain:{}", chain.id),
        Decision::Block => "block".to_string(),
    }
}

pub async fn connect(
    decision: Decision,
    host: &str,
    port: u16,
    egress: &EgressContext,
) -> Result<(Box<dyn IoStream>, EgressInfo)> {
    match decision {
        Decision::Direct => {
            let s = crate::resolver::tcp_connect_detailed(host, port)
                .await
                .map_err(|e| map_tcp_connect(format!("direct {host}:{port}"), e))?;
            let _ = s.set_nodelay(true);
            Ok((
                Box::new(s) as Box<dyn IoStream>,
                EgressInfo::single("direct".to_string()),
            ))
        }
        Decision::Via(up) => {
            let label = egress_label(&up);
            let stream = connect_upstream(up, host, port, egress).await?;
            Ok((stream, EgressInfo::single(label)))
        }
        Decision::ViaChain(chain) => connect_chain(&chain, host, port, egress).await,
        Decision::Block => Err(ProxyError::Blocked(host.to_string())),
    }
}

/// Dispatch one concrete upstream. Everything this performs is tunnel
/// establishment (dial, TLS/proxy handshake, CONNECT, reverse open), so any
/// error it returns is a valid trigger for chain failover; once it returns a
/// stream the member is fixed and later IO errors never replay elsewhere.
async fn connect_upstream(
    up: Upstream,
    host: &str,
    port: u16,
    egress: &EgressContext,
) -> Result<Box<dyn IoStream>> {
    match up.kind {
        UpstreamKind::Http => http_connect(up, host, port).await,
        UpstreamKind::Socks5 => socks5_connect(up, host, port).await,
        UpstreamKind::Reverse => reverse_connect(up, host, port, egress).await,
        UpstreamKind::Subnetra => subnetra_connect(host, port, egress).await,
    }
}

/// Try the chain's members in ascending-priority order — no randomization,
/// round-robin or parallel racing. Each attempt is bounded by
/// [`CHAIN_ATTEMPT_TIMEOUT`] and the whole request by [`CHAIN_TOTAL_TIMEOUT`];
/// when every member fails (or the budget runs out) the connection fails
/// closed with `ChainExhausted` — it never falls back to direct.
async fn connect_chain(
    chain: &Chain,
    host: &str,
    port: u16,
    egress: &EgressContext,
) -> Result<(Box<dyn IoStream>, EgressInfo)> {
    let deadline = Instant::now() + CHAIN_TOTAL_TIMEOUT;
    let mut attempts: u32 = 0;
    let mut last: Option<ProxyError> = None;
    for member in &chain.members {
        let Some(per_attempt) = remaining_budget(deadline, attempts) else {
            break;
        };
        attempts += 1;
        match tokio::time::timeout(
            per_attempt,
            connect_upstream(member.upstream.clone(), host, port, egress),
        )
        .await
        {
            Ok(Ok(stream)) => {
                if attempts > 1 {
                    debug!(
                        chain = %chain.id,
                        member = %member.id,
                        attempts,
                        "chain failover succeeded on backup member"
                    );
                }
                return Ok((
                    stream,
                    EgressInfo {
                        label: egress_label(&member.upstream),
                        chain_id: Some(chain.id.clone()),
                        member_id: Some(member.id.clone()),
                        attempts,
                    },
                ));
            }
            Ok(Err(e)) => {
                debug!(
                    chain = %chain.id,
                    member = %member.id,
                    stage = e.failure_stage(),
                    error = %e,
                    "chain member connect failed; trying next"
                );
                last = Some(e);
            }
            Err(_) => {
                let e = ProxyError::Upstream(format!(
                    "chain {} member {} attempt timed out after {per_attempt:?}",
                    chain.id, member.id
                ));
                debug!(
                    chain = %chain.id,
                    member = %member.id,
                    stage = "outbound",
                    error = %e,
                    "chain member connect timed out; trying next"
                );
                last = Some(e);
            }
        }
    }
    Err(ProxyError::ChainExhausted {
        chain: chain.id.clone(),
        attempts,
        last: Box::new(last.unwrap_or_else(|| {
            ProxyError::Upstream(format!("chain {} has no eligible members", chain.id))
        })),
    })
}

/// Per-attempt budget left before `deadline`, or `None` when the total
/// failover budget is spent. The first attempt always runs (the deadline
/// starts a full [`CHAIN_TOTAL_TIMEOUT`] away).
fn remaining_budget(deadline: Instant, attempts_so_far: u32) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() && attempts_so_far > 0 {
        return None;
    }
    Some(CHAIN_ATTEMPT_TIMEOUT.min(remaining.max(Duration::from_millis(1))))
}

/// Open a UDP relay for the client's association. In reverse/2 P0 **only**
/// reverse-hop egress carries UDP; every other decision fails closed (no direct,
/// HTTP-CONNECT cannot carry UDP, SOCKS5-upstream UDP is out of scope). For a
/// chain decision only its `reverse` members are eligible, tried in priority
/// order; non-UDP-capable members may exist in a mixed chain but are never
/// used for UDP. The association then sticks to the selected hop — the relay
/// is bound to it, so packets never migrate mid-session. The per-packet
/// destination is chosen later on [`crate::reverse::udp::UdpRelay`]; this call
/// only selects and opens the egress hop.
pub async fn connect_udp(
    decision: Decision,
    egress: &EgressContext,
) -> Result<(crate::reverse::udp::UdpRelay, EgressInfo)> {
    match decision {
        Decision::Via(up) if up.kind == UpstreamKind::Reverse => {
            let Some(manager) = egress.reverse() else {
                return Err(ProxyError::ReverseUnavailable(format!(
                    "reverse hop {} requested for udp but reverse data plane is not enabled",
                    up.addr
                )));
            };
            let relay = manager.open_udp(&up.addr).await?;
            let label = egress_label(&up);
            Ok((relay, EgressInfo::single(label)))
        }
        Decision::Via(up) => Err(ProxyError::Upstream(format!(
            "udp egress not supported via upstream kind {:?} ({})",
            up.kind, up.addr
        ))),
        Decision::ViaChain(chain) => connect_udp_chain(&chain, egress).await,
        Decision::Direct => Err(ProxyError::Upstream(
            "udp direct egress is out of scope for reverse/2 P0".to_string(),
        )),
        Decision::Block => Err(ProxyError::Blocked("udp".to_string())),
    }
}

/// UDP failover across a chain: only `reverse` members are UDP-capable, tried
/// in ascending priority under the same attempt/total budgets as TCP. A chain
/// with no reverse member fails closed (`attempts` = 0) instead of falling
/// back to direct or misusing an HTTP/SOCKS5 member.
async fn connect_udp_chain(
    chain: &Chain,
    egress: &EgressContext,
) -> Result<(crate::reverse::udp::UdpRelay, EgressInfo)> {
    let candidates: Vec<_> = chain
        .members
        .iter()
        .filter(|m| m.upstream.kind == UpstreamKind::Reverse)
        .collect();
    if candidates.is_empty() {
        return Err(ProxyError::ChainExhausted {
            chain: chain.id.clone(),
            attempts: 0,
            last: Box::new(ProxyError::Upstream(format!(
                "chain {} has no udp-capable (reverse) members",
                chain.id
            ))),
        });
    }
    let Some(manager) = egress.reverse() else {
        return Err(ProxyError::ChainExhausted {
            chain: chain.id.clone(),
            attempts: 0,
            last: Box::new(ProxyError::ReverseUnavailable(format!(
                "chain {} requested for udp but reverse data plane is not enabled",
                chain.id
            ))),
        });
    };

    let deadline = Instant::now() + CHAIN_TOTAL_TIMEOUT;
    let mut attempts: u32 = 0;
    let mut last: Option<ProxyError> = None;
    for member in candidates {
        let Some(per_attempt) = remaining_budget(deadline, attempts) else {
            break;
        };
        attempts += 1;
        match tokio::time::timeout(per_attempt, manager.open_udp(&member.upstream.addr)).await {
            Ok(Ok(relay)) => {
                return Ok((
                    relay,
                    EgressInfo {
                        label: egress_label(&member.upstream),
                        chain_id: Some(chain.id.clone()),
                        member_id: Some(member.id.clone()),
                        attempts,
                    },
                ));
            }
            Ok(Err(e)) => {
                debug!(
                    chain = %chain.id,
                    member = %member.id,
                    stage = e.failure_stage(),
                    error = %e,
                    "chain member udp open failed; trying next"
                );
                last = Some(e);
            }
            Err(_) => {
                let e = ProxyError::ReverseOpen(format!(
                    "chain {} member {} udp open timed out after {per_attempt:?}",
                    chain.id, member.id
                ));
                debug!(chain = %chain.id, member = %member.id, error = %e, "chain member udp open timed out; trying next");
                last = Some(e);
            }
        }
    }
    Err(ProxyError::ChainExhausted {
        chain: chain.id.clone(),
        attempts,
        last: Box::new(last.unwrap_or_else(|| {
            ProxyError::Upstream(format!("chain {} has no eligible udp members", chain.id))
        })),
    })
}

/// Route a target through an authenticated reverse-hop QUIC session. `up.addr`
/// is the `hop_id`. Fails closed — never falls back to direct — when the
/// reverse data plane is not configured or the hop is unavailable.
async fn reverse_connect(
    up: Upstream,
    host: &str,
    port: u16,
    egress: &EgressContext,
) -> Result<Box<dyn IoStream>> {
    let Some(manager) = egress.reverse() else {
        return Err(ProxyError::ReverseUnavailable(format!(
            "reverse hop {} requested but reverse data plane is not enabled",
            up.addr
        )));
    };
    manager.open(&up.addr, host, port).await
}

/// Route a target over the embedded Subnetra overlay (spoke egress). The target
/// host MUST be an overlay IPv4 address; the userspace IP stack dials it and
/// returns a stream. Fails closed — never falls back to direct — when subnetra is
/// not enabled or the host is not an overlay address.
async fn subnetra_connect(
    host: &str,
    port: u16,
    egress: &EgressContext,
) -> Result<Box<dyn IoStream>> {
    let Some(net) = egress.subnetra() else {
        return Err(ProxyError::Upstream(format!(
            "subnetra egress requested for {host}:{port} but subnetra is not enabled"
        )));
    };
    let ip: std::net::Ipv4Addr = host.parse().map_err(|_| {
        ProxyError::Upstream(format!(
            "subnetra egress target {host} is not an overlay IPv4 address"
        ))
    })?;
    let stream = net
        .connect(ip, port)
        .await
        .map_err(|e| ProxyError::Upstream(format!("subnetra connect {host}:{port}: {e}")))?;
    Ok(Box::new(stream))
}

fn map_tcp_connect(context: String, error: crate::resolver::TcpConnectError) -> ProxyError {
    match error {
        crate::resolver::TcpConnectError::Resolve(error) => {
            ProxyError::Dns(format!("{context}: {error}"))
        }
        crate::resolver::TcpConnectError::Dial(error) => {
            ProxyError::Dial(format!("{context}: {error}"))
        }
    }
}

/// TCP-connect to the upstream proxy, optionally wrapping in TLS.
async fn dial(up: &Upstream) -> Result<Box<dyn IoStream>> {
    let host = host_of(&up.addr);
    let port: u16 = up
        .addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .ok_or_else(|| ProxyError::Upstream(format!("bad upstream addr {}", up.addr)))?;
    let tcp = crate::resolver::tcp_connect_detailed(host, port)
        .await
        .map_err(|e| map_tcp_connect(format!("dial upstream {}", up.addr), e))?;
    let _ = tcp.set_nodelay(true);
    if up.tls {
        let connector = if up.skip_cert_verify {
            tls::insecure_client_connector()
        } else {
            tls::client_connector()
        };
        let sni = host_of(&up.addr).to_string();
        let server_name = ServerName::try_from(sni.as_str())
            .map_err(|e| ProxyError::Tls(format!("bad upstream sni {sni}: {e}")))?
            .to_owned();
        let stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| ProxyError::Tls(format!("upstream tls {}: {e}", up.addr)))?;
        Ok(Box::new(stream))
    } else {
        Ok(Box::new(tcp))
    }
}

async fn http_connect(up: Upstream, host: &str, port: u16) -> Result<Box<dyn IoStream>> {
    let mut stream = dial(&up).await?;
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(user) = &up.username {
        let pass = up.password.as_deref().unwrap_or("");
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;

    let head = read_http_head(&mut stream, 8192).await?;
    if !http_2xx(&head) {
        let first = String::from_utf8_lossy(&head);
        let line = first.lines().next().unwrap_or("");
        return Err(ProxyError::Upstream(format!(
            "http upstream refused: {line}"
        )));
    }
    Ok(stream)
}

async fn socks5_connect(up: Upstream, host: &str, port: u16) -> Result<Box<dyn IoStream>> {
    let mut stream = dial(&up).await?;
    let has_auth = up.username.is_some();

    // greeting
    if has_auth {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(ProxyError::Upstream("upstream bad socks version".into()));
    }
    match resp[1] {
        0x00 => {}
        0x02 => {
            let user = up.username.clone().unwrap_or_default();
            let pass = up.password.clone().unwrap_or_default();
            let mut buf = vec![0x01u8];
            buf.push(user.len() as u8);
            buf.extend_from_slice(user.as_bytes());
            buf.push(pass.len() as u8);
            buf.extend_from_slice(pass.as_bytes());
            stream.write_all(&buf).await?;
            let mut ar = [0u8; 2];
            stream.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                return Err(ProxyError::Upstream("upstream socks auth failed".into()));
            }
        }
        m => {
            return Err(ProxyError::Upstream(format!(
                "upstream socks method {m:#x}"
            )))
        }
    }

    // CONNECT request (domain form)
    let hb = host.as_bytes();
    if hb.len() > 255 {
        return Err(ProxyError::Upstream("hostname too long".into()));
    }
    let mut req = vec![0x05u8, 0x01, 0x00, 0x03, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    // reply
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(ProxyError::Upstream(format!(
            "upstream socks reply {:#x}",
            head[1]
        )));
    }
    // drain BND.ADDR + BND.PORT
    match head[3] {
        0x01 => {
            let mut a = [0u8; 4 + 2];
            stream.read_exact(&mut a).await?;
        }
        0x04 => {
            let mut a = [0u8; 16 + 2];
            stream.read_exact(&mut a).await?;
        }
        0x03 => {
            let l = read_u8(&mut stream).await? as usize;
            let mut a = vec![0u8; l + 2];
            stream.read_exact(&mut a).await?;
        }
        _ => return Err(ProxyError::Upstream("upstream bad bnd atyp".into())),
    }
    Ok(stream)
}

async fn read_u8<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> std::io::Result<u8> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    Ok(b[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ChainMember;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    #[tokio::test]
    async fn direct_connect_tunnels_bytes() {
        let (addr, task) = start_echo_server().await;

        let (mut stream, egress) = connect(
            Decision::Direct,
            "127.0.0.1",
            addr.port(),
            &EgressContext::default(),
        )
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();

        assert_eq!(&echoed, b"ping");
        assert_eq!(egress.label, "direct");
        assert_eq!(egress.attempts, 1);
        assert!(egress.chain_id.is_none() && egress.member_id.is_none());
        drop(stream);
        task.await.unwrap();
    }

    // -----------------------------------------------------------------
    // Failover chains
    // -----------------------------------------------------------------

    fn member(id: &str, priority: u32, kind: UpstreamKind, addr: String) -> ChainMember {
        ChainMember {
            id: id.to_string(),
            priority,
            upstream: Upstream {
                kind,
                addr,
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            },
        }
    }

    fn chain(id: &str, mut members: Vec<ChainMember>) -> Decision {
        members.sort_by_key(|m| m.priority);
        Decision::ViaChain(Arc::new(Chain {
            id: id.to_string(),
            members,
        }))
    }

    /// A port that refuses connections: bind, take the port, drop the
    /// listener.
    async fn dead_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr.to_string()
    }

    #[tokio::test]
    async fn chain_fails_over_to_secondary_member_during_establishment() {
        let dead = dead_addr().await;
        let (backup, task) =
            start_http_upstream("HTTP/1.1 200 Connection Established", false).await;
        let decision = chain(
            "jp-pop",
            vec![
                member("jp-primary", 1, UpstreamKind::Http, dead),
                member("jp-backup", 2, UpstreamKind::Http, backup.to_string()),
            ],
        );

        let (mut stream, egress) =
            connect(decision, "target.example", 443, &EgressContext::default())
                .await
                .expect("failover must succeed via backup");
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");

        assert_eq!(egress.chain_id.as_deref(), Some("jp-pop"));
        assert_eq!(egress.member_id.as_deref(), Some("jp-backup"));
        assert_eq!(egress.attempts, 2);
        assert_eq!(egress.label, format!("upstream:{backup}"));
        drop(stream);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn chain_reverse_primary_fails_over_to_address_backend() {
        // The reverse primary is unavailable (no reverse data plane); the
        // dialed socks5-style backup must win instead of failing the request.
        let (backup, task) =
            start_http_upstream("HTTP/1.1 200 Connection Established", false).await;
        let decision = chain(
            "jp-pop",
            vec![
                member("jp-reverse-1", 1, UpstreamKind::Reverse, "h1".to_string()),
                member("jp-http-2", 2, UpstreamKind::Http, backup.to_string()),
            ],
        );

        let (mut stream, egress) =
            connect(decision, "target.example", 443, &EgressContext::default())
                .await
                .expect("failover must succeed via address backend");
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();

        assert_eq!(egress.member_id.as_deref(), Some("jp-http-2"));
        assert_eq!(egress.attempts, 2);
        drop(stream);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn chain_exhausted_fails_closed_with_attempt_count() {
        let dead1 = dead_addr().await;
        let dead2 = dead_addr().await;
        let decision = chain(
            "jp-pop",
            vec![
                member("m1", 1, UpstreamKind::Http, dead1),
                member("m2", 2, UpstreamKind::Socks5, dead2),
            ],
        );

        let err = expect_connect_error(
            connect(decision, "target.example", 443, &EgressContext::default()).await,
        );
        assert_eq!(err.failure_stage(), "chain_exhausted");
        assert_eq!(err.chain_attempts(), Some(2));
        let text = err.to_string();
        assert!(text.contains("chain jp-pop exhausted after 2 attempts"));
    }

    #[tokio::test]
    async fn chain_member_is_pinned_after_establishment() {
        // Once a member returned an established stream, later IO on that
        // stream must never be replayed onto other members.
        let (winner, task) =
            start_http_upstream("HTTP/1.1 200 Connection Established", false).await;
        let standby = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let standby_addr = standby.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = accepted.clone();
        let standby_task = tokio::spawn(async move {
            while standby.accept().await.is_ok() {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let decision = chain(
            "jp-pop",
            vec![
                member("winner", 1, UpstreamKind::Http, winner.to_string()),
                member("standby", 2, UpstreamKind::Http, standby_addr.to_string()),
            ],
        );
        let (mut stream, egress) =
            connect(decision, "target.example", 443, &EgressContext::default())
                .await
                .unwrap();
        assert_eq!(egress.member_id.as_deref(), Some("winner"));
        assert_eq!(egress.attempts, 1);

        // Drive the tunnel to completion (echo) and drop it: the upstream
        // closes; nothing may dial the standby at any point.
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();
        drop(stream);
        task.await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0);
        standby_task.abort();
    }

    #[tokio::test]
    async fn chain_udp_requires_a_reverse_member() {
        let decision = chain(
            "tcp-only",
            vec![
                member("m1", 1, UpstreamKind::Http, "10.0.0.1:8080".to_string()),
                member("m2", 2, UpstreamKind::Socks5, "10.0.0.2:1080".to_string()),
            ],
        );
        let err = match connect_udp(decision, &EgressContext::default()).await {
            Ok(_) => panic!("udp over a tcp-only chain must fail closed"),
            Err(e) => e,
        };
        assert_eq!(err.failure_stage(), "chain_exhausted");
        assert_eq!(err.chain_attempts(), Some(0));
        assert!(err.to_string().contains("no udp-capable (reverse) members"));
    }

    #[tokio::test]
    async fn chain_udp_only_tries_reverse_members_and_fails_closed_without_manager() {
        let decision = chain(
            "mixed",
            vec![
                member(
                    "socks",
                    1,
                    UpstreamKind::Socks5,
                    "10.0.0.2:1080".to_string(),
                ),
                member("hop", 2, UpstreamKind::Reverse, "h1".to_string()),
            ],
        );
        let err = match connect_udp(decision, &EgressContext::default()).await {
            Ok(_) => panic!("udp without a reverse data plane must fail closed"),
            Err(e) => e,
        };
        // The reverse member is eligible but the data plane is missing:
        // fail-closed before any attempt, never via the socks5 member.
        assert_eq!(err.failure_stage(), "chain_exhausted");
        assert!(err
            .to_string()
            .contains("reverse data plane is not enabled"));
    }

    #[tokio::test]
    async fn block_decision_returns_policy_error() {
        let err = expect_connect_error(
            connect(
                Decision::Block,
                "blocked.example",
                443,
                &EgressContext::default(),
            )
            .await,
        );

        assert!(err.to_string().contains("target blocked by policy"));
    }

    #[tokio::test]
    async fn reverse_upstream_without_manager_fails_closed() {
        let up = Upstream {
            kind: UpstreamKind::Reverse,
            addr: "hop-s604".to_string(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        };

        let err = expect_connect_error(
            connect(
                Decision::Via(up),
                "target.example",
                443,
                &EgressContext::default(),
            )
            .await,
        );

        // Fails closed with the reverse_lookup stage; never falls back to direct.
        assert_eq!(err.failure_stage(), "reverse_lookup");
        assert!(err
            .to_string()
            .contains("reverse data plane is not enabled"));
    }

    #[tokio::test]
    async fn http_upstream_connects_with_basic_auth_and_tunnels() {
        let (addr, task) = start_http_upstream("HTTP/1.1 200 Connection Established", true).await;
        let up = Upstream {
            kind: UpstreamKind::Http,
            addr: addr.to_string(),
            username: Some("proxy-user".to_string()),
            password: Some("proxy-pass".to_string()),
            tls: false,
            skip_cert_verify: false,
        };

        let (mut stream, _egress) = connect(
            Decision::Via(up),
            "target.example",
            443,
            &EgressContext::default(),
        )
        .await
        .unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        stream.read_exact(&mut echoed).await.unwrap();

        assert_eq!(&echoed, b"hello");
        drop(stream);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn http_upstream_refusal_is_reported() {
        let (addr, task) =
            start_http_upstream("HTTP/1.1 407 Proxy Authentication Required", false).await;
        let up = Upstream {
            kind: UpstreamKind::Http,
            addr: addr.to_string(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        };

        let err = expect_connect_error(
            connect(
                Decision::Via(up),
                "target.example",
                443,
                &EgressContext::default(),
            )
            .await,
        );

        assert!(err.to_string().contains("http upstream refused"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_upstream_connects_with_auth_and_tunnels() {
        let (addr, task) = start_socks5_upstream(true, 0x02, 0x01).await;
        let up = Upstream {
            kind: UpstreamKind::Socks5,
            addr: addr.to_string(),
            username: Some("proxy-user".to_string()),
            password: Some("proxy-pass".to_string()),
            tls: false,
            skip_cert_verify: false,
        };

        let (mut stream, _egress) = connect(
            Decision::Via(up),
            "target.example",
            8443,
            &EgressContext::default(),
        )
        .await
        .unwrap();
        stream.write_all(b"pong").await.unwrap();
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();

        assert_eq!(&echoed, b"pong");
        drop(stream);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_upstream_failures_are_reported() {
        let (addr, task) = start_socks5_upstream(false, 0x09, 0x01).await;
        let up = Upstream {
            kind: UpstreamKind::Socks5,
            addr: addr.to_string(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        };

        let err = expect_connect_error(
            connect(
                Decision::Via(up),
                "target.example",
                8443,
                &EgressContext::default(),
            )
            .await,
        );

        assert!(err.to_string().contains("upstream socks method"));
        task.await.unwrap();
    }

    fn expect_connect_error<T>(result: Result<T>) -> ProxyError {
        match result {
            Ok(_) => panic!("connect unexpectedly succeeded"),
            Err(err) => err,
        }
    }

    #[tokio::test]
    async fn tls_upstream_with_self_signed_cert_is_rejected_by_default() {
        crate::tls::init_crypto();
        let (port, cert_path, key_path, task) = spawn_self_signed_tls_server().await;
        let up = Upstream {
            kind: UpstreamKind::Http,
            addr: format!("localhost:{port}"),
            username: None,
            password: None,
            tls: true,
            skip_cert_verify: false,
        };

        let err = expect_connect_error(dial(&up).await);
        assert!(err.to_string().contains("upstream tls"));

        task.abort();
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(key_path);
    }

    #[tokio::test]
    async fn tls_upstream_with_skip_cert_verify_accepts_self_signed_cert() {
        crate::tls::init_crypto();
        let (port, cert_path, key_path, task) = spawn_self_signed_tls_server().await;
        let up = Upstream {
            kind: UpstreamKind::Http,
            addr: format!("localhost:{port}"),
            username: None,
            password: None,
            tls: true,
            skip_cert_verify: true,
        };

        let mut stream = dial(&up).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        task.await.unwrap();
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(key_path);
    }

    async fn spawn_self_signed_tls_server() -> (u16, String, String, JoinHandle<()>) {
        let cert_path = tls_temp_path("outbound-it.crt");
        let key_path = tls_temp_path("outbound-it.key");
        std::fs::write(&cert_path, crate::tls::tests::TEST_CERT).unwrap();
        std::fs::write(&key_path, crate::tls::tests::TEST_KEY).unwrap();
        let acceptor = crate::tls::server_acceptor(&cert_path, &key_path).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(socket).await else {
                return;
            };
            let mut buf = [0u8; 16];
            if let Ok(n) = tls.read(&mut buf).await {
                if n > 0 {
                    let _ = tls.write_all(&buf[..n]).await;
                }
            }
        });
        (port, cert_path, key_path, task)
    }

    fn tls_temp_path(name: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rove-outbound-{nanos}-{name}"))
            .to_string_lossy()
            .into_owned()
    }

    async fn start_echo_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });
        (addr, task)
    }

    async fn start_http_upstream(
        status: &'static str,
        expect_auth: bool,
    ) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let head = read_http_head(&mut socket, 8192).await.unwrap();
            let text = String::from_utf8_lossy(&head);
            assert!(text.starts_with("CONNECT target.example:443 HTTP/1.1"));
            if expect_auth {
                let token =
                    base64::engine::general_purpose::STANDARD.encode("proxy-user:proxy-pass");
                assert!(text.contains(&format!("Proxy-Authorization: Basic {token}")));
            }
            socket
                .write_all(format!("{status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .await
                .unwrap();
            if status.contains("200") {
                let mut buf = [0u8; 16];
                let n = socket.read(&mut buf).await.unwrap();
                socket.write_all(&buf[..n]).await.unwrap();
            }
        });
        (addr, task)
    }

    async fn start_socks5_upstream(
        expect_auth: bool,
        method: u8,
        reply_atyp: u8,
    ) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 0x05);
            socket.write_all(&[0x05, method]).await.unwrap();
            if method != 0x00 && method != 0x02 {
                return;
            }

            if expect_auth {
                let ver = read_u8(&mut socket).await.unwrap();
                assert_eq!(ver, 0x01);
                let user_len = read_u8(&mut socket).await.unwrap() as usize;
                let mut user = vec![0u8; user_len];
                socket.read_exact(&mut user).await.unwrap();
                let pass_len = read_u8(&mut socket).await.unwrap() as usize;
                let mut pass = vec![0u8; pass_len];
                socket.read_exact(&mut pass).await.unwrap();
                assert_eq!(&user, b"proxy-user");
                assert_eq!(&pass, b"proxy-pass");
                socket.write_all(&[0x01, 0x00]).await.unwrap();
            }

            let mut head = [0u8; 5];
            socket.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..4], &[0x05, 0x01, 0x00, 0x03]);
            let mut host = vec![0u8; head[4] as usize];
            socket.read_exact(&mut host).await.unwrap();
            assert_eq!(&host, b"target.example");
            let mut port = [0u8; 2];
            socket.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 8443);

            match reply_atyp {
                0x01 => {
                    socket
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                }
                0x03 => {
                    socket
                        .write_all(&[0x05, 0x00, 0x00, 0x03, 4, b't', b'e', b's', b't', 0, 0])
                        .await
                        .unwrap();
                }
                _ => unreachable!(),
            }

            let mut buf = [0u8; 16];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
        });
        (addr, task)
    }
}
