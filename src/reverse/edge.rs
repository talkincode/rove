//! Edge-side reverse-hop control: accept authenticated hop QUIC connections,
//! track `hop_id -> connection`, and open one bidirectional stream per proxied
//! user tunnel.
//!
//! This is the only place the edge holds reverse-hop state. It is created only
//! when `[reverse_hop].enable` is set, and the rest of the data plane reaches
//! it through [`ReverseHopManager::open`], which returns a
//! [`crate::io::IoStream`] indistinguishable from any other egress so the
//! existing splice / limit / access-log path is reused unchanged.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

use super::frame::{self, codes, AssociateRequest, RegisterRequest, Reply, TunnelRequest};
use super::udp::{self, EdgeUdpConn, UdpRelay};
use super::{QuicDuplex, CLOSE_OK, DEFAULT_MAX_STREAMS_PER_HOP, DEFAULT_OPEN_TIMEOUT};
use crate::error::{ProxyError, Result};
use crate::io::IoStream;
use crate::util::constant_time_eq;

/// What to do when a hop registers a `hop_id` that already has a live session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicatePolicy {
    /// Keep the existing session; refuse the newcomer with `duplicate_hop_id`.
    /// Default — deterministic and safe against a flapping hop stealing routes.
    Reject,
    /// Evict and close the existing session, then accept the newcomer. Useful
    /// when a hop reconnects after an ungraceful drop the edge has not noticed.
    Replace,
}

impl DuplicatePolicy {
    /// Parse the operator-facing string form; unknown values are rejected so a
    /// typo cannot silently pick an unintended policy.
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "reject" => Ok(DuplicatePolicy::Reject),
            "replace" => Ok(DuplicatePolicy::Replace),
            other => {
                anyhow::bail!("reverse_hop duplicate policy must be reject|replace, got {other:?}")
            }
        }
    }
}

/// Static configuration for the edge reverse-hop listener.
#[derive(Debug, Clone)]
pub struct ReverseListenerConfig {
    /// UDP `ip:port` the QUIC endpoint binds to.
    pub listen: String,
    /// PEM certificate / key the edge presents to hops (QUIC mandates TLS 1.3).
    pub cert: String,
    pub key: String,
    /// Accepted registration tokens. At least one is required; multiple lets
    /// distinct hops carry distinct secrets. Never logged.
    pub tokens: Vec<String>,
    pub duplicate: DuplicatePolicy,
    /// Per-hop concurrent-tunnel ceiling (also the QUIC bidi-stream cap).
    pub max_streams_per_hop: u32,
    /// How long to wait for a hop to accept a tunnel `CONNECT` before failing
    /// closed with stage `reverse_open`.
    pub open_timeout: Duration,
    /// This edge's identity, attached to logs/metrics (`edge_id` dimension).
    pub edge_id: String,
    /// Optional fixed QUIC path MTU (max UDP-payload bytes) for an already-
    /// compressed outer tunnel. `None` keeps quinn's default PMTUD.
    pub initial_mtu: Option<u16>,
}

impl ReverseListenerConfig {
    pub fn new(
        listen: impl Into<String>,
        cert: impl Into<String>,
        key: impl Into<String>,
        tokens: Vec<String>,
        edge_id: impl Into<String>,
    ) -> Self {
        ReverseListenerConfig {
            listen: listen.into(),
            cert: cert.into(),
            key: key.into(),
            tokens,
            duplicate: DuplicatePolicy::Reject,
            max_streams_per_hop: DEFAULT_MAX_STREAMS_PER_HOP,
            open_timeout: DEFAULT_OPEN_TIMEOUT,
            edge_id: edge_id.into(),
            initial_mtu: None,
        }
    }
}

/// One authenticated hop connection plus its per-hop concurrency accounting.
/// Cheap to clone: every field is either a quinn handle or an `Arc`.
#[derive(Clone)]
struct HopSession {
    connection: quinn::Connection,
    /// Bounds edge-initiated tunnels; also feeds the fail-closed at-capacity
    /// path so we never queue unboundedly behind a saturated hop.
    permits: Arc<Semaphore>,
    /// Live tunnel gauge for observability.
    active: Arc<AtomicUsize>,
    edge_id: Option<String>,
    /// quinn's per-connection unique id, used so a stale connection's cleanup
    /// task cannot evict a newer session that reused the same `hop_id`.
    stable_id: usize,
    remote: SocketAddr,
    /// Whether the hop advertised `caps: udp`; gates UDP association routing so
    /// the edge fails closed rather than opening a UDP stream a v1 hop ignores.
    supports_udp: bool,
    /// Per-connection UDP demux state (session_id -> return-packet channel).
    udp: Arc<EdgeUdpConn>,
}

/// Edge-side registry and tunnel opener. Cloneable handle (`Arc` internally).
pub struct ReverseHopManager {
    registry: Mutex<HashMap<String, HopSession>>,
    tokens: Vec<String>,
    duplicate: DuplicatePolicy,
    max_streams_per_hop: u32,
    open_timeout: Duration,
    edge_id: String,
    tunnel_seq: AtomicU64,
    local_addr: SocketAddr,
}

enum RegisterOutcome {
    Accepted,
    Duplicate,
}

/// Grace period to let a rejection reply flush to the hop before the
/// `CONNECTION_CLOSE` would otherwise discard the unacknowledged stream data.
/// Bounded so a peer that never reads cannot pin the accept task; on loopback
/// and normal networks the reply is delivered and acknowledged well within it.
const REJECT_LINGER: Duration = Duration::from_millis(500);

/// Write a terminal `ERR` reply, finish the stream, then close the connection
/// once the reply has had a chance to reach the hop (or the linger elapses), so
/// the hop can log the stable error code rather than a bare connection loss.
async fn reject_registration(
    connection: &quinn::Connection,
    mut send: quinn::SendStream,
    reply: Reply,
    reason: &[u8],
) {
    let _ = frame::write_frame(&mut send, &reply.encode()).await;
    let _ = send.finish();
    let _ = tokio::time::timeout(REJECT_LINGER, connection.closed()).await;
    connection.close(CLOSE_OK.into(), reason);
}

impl ReverseHopManager {
    /// Bind the QUIC endpoint and start accepting hop registrations. Must be
    /// called from within a Tokio runtime.
    pub fn spawn(config: ReverseListenerConfig) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            !config.tokens.is_empty(),
            "reverse_hop requires at least one registration token"
        );
        anyhow::ensure!(
            config.tokens.iter().all(|t| !t.trim().is_empty()),
            "reverse_hop tokens must not be empty strings"
        );
        let max_streams = config.max_streams_per_hop.max(1);
        let server_cfg =
            super::server_config(&config.cert, &config.key, max_streams, config.initial_mtu)?;
        let addr: SocketAddr = config
            .listen
            .parse()
            .map_err(|e| anyhow::anyhow!("reverse_hop listen {:?}: {e}", config.listen))?;
        let endpoint = quinn::Endpoint::server(server_cfg, addr)
            .map_err(|e| anyhow::anyhow!("reverse_hop bind {addr}: {e}"))?;
        let bound = endpoint.local_addr().unwrap_or(addr);

        let manager = Arc::new(ReverseHopManager {
            registry: Mutex::new(HashMap::new()),
            tokens: config.tokens,
            duplicate: config.duplicate,
            max_streams_per_hop: max_streams,
            open_timeout: config.open_timeout,
            edge_id: config.edge_id,
            tunnel_seq: AtomicU64::new(1),
            local_addr: bound,
        });
        info!(
            edge_id = %manager.edge_id,
            listen = %bound,
            duplicate = ?manager.duplicate,
            max_streams_per_hop = max_streams,
            "reverse-hop QUIC listener started"
        );
        tokio::spawn(manager.clone().accept_loop(endpoint));
        Ok(manager)
    }

    /// Open one reverse tunnel to `hop_id` for `host:port`. Fails closed with a
    /// stable [`ProxyError`] whose `failure_stage()` distinguishes
    /// `reverse_lookup` / `reverse_open` / `hop_connect`.
    pub async fn open(&self, hop_id: &str, host: &str, port: u16) -> Result<Box<dyn IoStream>> {
        let session = self
            .registry
            .lock()
            .expect("reverse registry poisoned")
            .get(hop_id)
            .cloned();
        let Some(session) = session else {
            return Err(ProxyError::ReverseUnavailable(format!(
                "no authenticated reverse session for hop_id {hop_id}"
            )));
        };

        // Fail closed rather than queue behind a saturated hop.
        let permit = match session.permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                return Err(ProxyError::ReverseHopConnect(format!(
                    "hop {hop_id} at per-hop stream capacity"
                )))
            }
        };

        let tunnel_id = format!(
            "{}-{}",
            self.edge_id,
            self.tunnel_seq.fetch_add(1, Ordering::Relaxed)
        );
        let (mut send, mut recv) =
            match tokio::time::timeout(self.open_timeout, session.connection.open_bi()).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    return Err(ProxyError::ReverseOpen(format!(
                        "open stream to hop {hop_id}: {e}"
                    )))
                }
                Err(_) => {
                    return Err(ProxyError::ReverseOpen(format!(
                        "open stream to hop {hop_id} timed out"
                    )))
                }
            };

        let request = TunnelRequest {
            host: host.to_string(),
            port,
            tunnel_id: Some(tunnel_id.clone()),
        };
        if let Err(e) = frame::write_frame(&mut send, &request.encode()).await {
            return Err(ProxyError::ReverseOpen(format!(
                "send CONNECT to hop {hop_id}: {e}"
            )));
        }

        let reply_lines =
            match tokio::time::timeout(self.open_timeout, frame::read_frame(&mut recv)).await {
                Ok(Ok(lines)) => lines,
                Ok(Err(e)) => {
                    return Err(ProxyError::ReverseOpen(format!(
                        "read reply from hop {hop_id}: {e}"
                    )))
                }
                Err(_) => {
                    return Err(ProxyError::ReverseOpen(format!(
                        "reply from hop {hop_id} timed out"
                    )))
                }
            };

        match Reply::parse(&reply_lines) {
            Ok(Reply::Ok) => {
                session.active.fetch_add(1, Ordering::Relaxed);
                debug!(
                    edge_id = %self.edge_id,
                    hop_id = %hop_id,
                    hop_edge_id = ?session.edge_id,
                    tunnel_id = %tunnel_id,
                    target = %format!("{host}:{port}"),
                    remote = %session.remote,
                    "reverse tunnel opened"
                );
                Ok(Box::new(GuardedTunnel {
                    duplex: QuicDuplex::new(send, recv),
                    _permit: permit,
                    _active: ActiveGuard(session.active.clone()),
                }))
            }
            Ok(Reply::Err(code)) => Err(ProxyError::ReverseHopConnect(format!(
                "hop {hop_id} refused tunnel: {code}"
            ))),
            Err(e) => Err(ProxyError::ReverseOpen(format!(
                "malformed reply from hop {hop_id}: {e}"
            ))),
        }
    }

    /// Open a UDP association to `hop_id`, returning a [`UdpRelay`] egress
    /// handle. Fails closed when the hop did not advertise UDP support, is at
    /// per-hop session capacity, or refuses the association — never downgraded.
    pub async fn open_udp(&self, hop_id: &str) -> Result<UdpRelay> {
        let session = self
            .registry
            .lock()
            .expect("reverse registry poisoned")
            .get(hop_id)
            .cloned();
        let Some(session) = session else {
            return Err(ProxyError::ReverseUnavailable(format!(
                "no authenticated reverse session for hop_id {hop_id}"
            )));
        };
        if !session.supports_udp {
            return Err(ProxyError::ReverseHopConnect(format!(
                "hop {hop_id} does not advertise udp support"
            )));
        }
        let permit = match session.permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                return Err(ProxyError::ReverseHopConnect(format!(
                    "hop {hop_id} at per-hop session capacity"
                )))
            }
        };
        let session_id = session.udp.next_session_id();
        let assoc_id = format!(
            "{}-u{}",
            self.edge_id,
            self.tunnel_seq.fetch_add(1, Ordering::Relaxed)
        );
        let (mut send, mut recv) =
            match tokio::time::timeout(self.open_timeout, session.connection.open_bi()).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    return Err(ProxyError::ReverseOpen(format!(
                        "open udp control stream to hop {hop_id}: {e}"
                    )))
                }
                Err(_) => {
                    return Err(ProxyError::ReverseOpen(format!(
                        "open udp control stream to hop {hop_id} timed out"
                    )))
                }
            };
        let request = AssociateRequest {
            session_id,
            assoc_id: Some(assoc_id),
        };
        if let Err(e) = frame::write_frame(&mut send, &request.encode()).await {
            return Err(ProxyError::ReverseOpen(format!(
                "send ASSOCIATE to hop {hop_id}: {e}"
            )));
        }
        let reply_lines =
            match tokio::time::timeout(self.open_timeout, frame::read_frame(&mut recv)).await {
                Ok(Ok(lines)) => lines,
                Ok(Err(e)) => {
                    return Err(ProxyError::ReverseOpen(format!(
                        "read ASSOCIATE reply from hop {hop_id}: {e}"
                    )))
                }
                Err(_) => {
                    return Err(ProxyError::ReverseOpen(format!(
                        "ASSOCIATE reply from hop {hop_id} timed out"
                    )))
                }
            };
        match Reply::parse(&reply_lines) {
            Ok(Reply::Ok) => {
                debug!(
                    edge_id = %self.edge_id,
                    hop_id = %hop_id,
                    session_id,
                    "reverse udp association opened"
                );
                Ok(udp::build_relay(
                    session.connection.clone(),
                    session_id,
                    session.udp.clone(),
                    send,
                    recv,
                    permit,
                ))
            }
            Ok(Reply::Err(code)) => Err(ProxyError::ReverseHopConnect(format!(
                "hop {hop_id} refused udp association: {code}"
            ))),
            Err(e) => Err(ProxyError::ReverseOpen(format!(
                "malformed udp reply from hop {hop_id}: {e}"
            ))),
        }
    }

    /// Number of currently registered hop sessions (inspection / tests).
    pub fn session_count(&self) -> usize {
        self.registry
            .lock()
            .expect("reverse registry poisoned")
            .len()
    }

    /// The actual bound UDP address (useful when the config used port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// True if `hop_id` currently has an authenticated session.
    pub fn is_registered(&self, hop_id: &str) -> bool {
        self.registry
            .lock()
            .expect("reverse registry poisoned")
            .contains_key(hop_id)
    }

    fn token_accepted(&self, token: &str) -> bool {
        self.tokens.iter().any(|t| constant_time_eq(t, token))
    }

    fn register(
        &self,
        hop_id: &str,
        connection: quinn::Connection,
        remote: SocketAddr,
        edge_id: Option<String>,
        supports_udp: bool,
        udp: Arc<EdgeUdpConn>,
    ) -> RegisterOutcome {
        let mut reg = self.registry.lock().expect("reverse registry poisoned");
        if reg.contains_key(hop_id) {
            match self.duplicate {
                DuplicatePolicy::Reject => return RegisterOutcome::Duplicate,
                DuplicatePolicy::Replace => {
                    if let Some(old) = reg.remove(hop_id) {
                        old.connection
                            .close(CLOSE_OK.into(), b"replaced by new registration");
                    }
                }
            }
        }
        let stable_id = connection.stable_id();
        reg.insert(
            hop_id.to_string(),
            HopSession {
                connection,
                permits: Arc::new(Semaphore::new(self.max_streams_per_hop as usize)),
                active: Arc::new(AtomicUsize::new(0)),
                edge_id,
                stable_id,
                remote,
                supports_udp,
                udp,
            },
        );
        RegisterOutcome::Accepted
    }

    fn deregister(&self, hop_id: &str, stable_id: usize) {
        let mut reg = self.registry.lock().expect("reverse registry poisoned");
        if reg.get(hop_id).map(|s| s.stable_id) == Some(stable_id) {
            reg.remove(hop_id);
        }
    }

    async fn accept_loop(self: Arc<Self>, endpoint: quinn::Endpoint) {
        while let Some(incoming) = endpoint.accept().await {
            let manager = self.clone();
            tokio::spawn(async move {
                let remote = incoming.remote_address();
                let connection = match incoming.accept() {
                    Ok(connecting) => match connecting.await {
                        Ok(conn) => conn,
                        Err(e) => {
                            debug!(remote = %remote, error = %e, "reverse hop handshake failed");
                            return;
                        }
                    },
                    Err(e) => {
                        debug!(remote = %remote, error = %e, "reverse hop accept failed");
                        return;
                    }
                };
                manager.handle_connection(connection, remote).await;
            });
        }
    }

    async fn handle_connection(&self, connection: quinn::Connection, remote: SocketAddr) {
        // The hop's first bidirectional stream is the control/register stream.
        let (mut send, mut recv) =
            match tokio::time::timeout(self.open_timeout, connection.accept_bi()).await {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    debug!(remote = %remote, error = %e, "reverse hop opened no control stream");
                    connection.close(CLOSE_OK.into(), b"no control stream");
                    return;
                }
                Err(_) => {
                    debug!(remote = %remote, "reverse hop register timed out");
                    connection.close(CLOSE_OK.into(), b"register timeout");
                    return;
                }
            };

        let lines = match frame::read_frame(&mut recv).await {
            Ok(lines) => lines,
            Err(e) => {
                debug!(remote = %remote, error = %e, "reverse register frame unreadable");
                connection.close(CLOSE_OK.into(), b"bad register frame");
                return;
            }
        };
        let request = match RegisterRequest::parse(&lines) {
            Ok(req) => req,
            Err(e) => {
                debug!(remote = %remote, error = %e, "reverse register frame malformed");
                reject_registration(
                    &connection,
                    send,
                    Reply::Err(codes::BAD_REQUEST.into()),
                    b"malformed register",
                )
                .await;
                return;
            }
        };

        if !self.token_accepted(&request.token) {
            warn!(
                edge_id = %self.edge_id,
                hop_id = %request.hop_id,
                remote = %remote,
                "reverse hop registration rejected: unauthorized"
            );
            reject_registration(
                &connection,
                send,
                Reply::Err(codes::UNAUTHORIZED.into()),
                b"unauthorized",
            )
            .await;
            return;
        }

        let supports_udp = request.supports_udp();
        let udp = Arc::new(EdgeUdpConn::default());
        match self.register(
            &request.hop_id,
            connection.clone(),
            remote,
            request.edge_id.clone(),
            supports_udp,
            udp.clone(),
        ) {
            RegisterOutcome::Accepted => {
                if let Err(e) = frame::write_frame(&mut send, &Reply::Ok.encode()).await {
                    debug!(hop_id = %request.hop_id, error = %e, "reverse register ack failed");
                    self.deregister(&request.hop_id, connection.stable_id());
                    connection.close(CLOSE_OK.into(), b"ack failed");
                    return;
                }
                // Start the per-connection datagram reader only for UDP-capable
                // hops; it routes hop->edge return packets to associations.
                if supports_udp {
                    udp::spawn_edge_demux(connection.clone(), udp.clone());
                }
                info!(
                    edge_id = %self.edge_id,
                    hop_id = %request.hop_id,
                    remote = %remote,
                    hop_edge_id = ?request.edge_id,
                    udp = supports_udp,
                    "reverse hop registered"
                );
            }
            RegisterOutcome::Duplicate => {
                warn!(
                    edge_id = %self.edge_id,
                    hop_id = %request.hop_id,
                    remote = %remote,
                    "reverse hop registration rejected: duplicate hop_id"
                );
                reject_registration(
                    &connection,
                    send,
                    Reply::Err(codes::DUPLICATE_HOP_ID.into()),
                    b"duplicate hop_id",
                )
                .await;
                return;
            }
        }

        // Hold the session open until the connection ends, then deregister —
        // but only if we still own the slot (Replace may have handed it on).
        let reason = connection.closed().await;
        self.deregister(&request.hop_id, connection.stable_id());
        info!(
            edge_id = %self.edge_id,
            hop_id = %request.hop_id,
            reason = %reason,
            "reverse hop deregistered"
        );
    }
}

/// Decrement the per-hop live-tunnel gauge when a tunnel stream is dropped.
struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A reverse tunnel stream that keeps its per-hop concurrency permit and live
/// gauge alive for exactly the tunnel's lifetime, delegating all IO to the
/// underlying [`QuicDuplex`]. Both guards are held purely for their `Drop`.
struct GuardedTunnel {
    duplex: QuicDuplex,
    _permit: OwnedSemaphorePermit,
    _active: ActiveGuard,
}

impl AsyncRead for GuardedTunnel {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.duplex).poll_read(cx, buf)
    }
}

impl AsyncWrite for GuardedTunnel {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.duplex).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.duplex).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.duplex).poll_shutdown(cx)
    }
}
