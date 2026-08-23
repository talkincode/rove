//! reverse/2 UDP relay data plane.
//!
//! UDP packets ride the connection's **QUIC datagrams** (unreliable, matching
//! UDP semantics — no head-of-line blocking, no retransmit); a per-association
//! **control bi-stream** carries `ASSOCIATE` / `DISSOCIATE` setup and teardown.
//! The edge assigns a `session_id` per association (unique within one hop
//! connection); every datagram is tagged with it plus a per-packet destination
//! (see [`super::frame::Datagram`]), so one association can reach many targets,
//! exactly like SOCKS5 UDP.
//!
//! Hop-side NAT is **endpoint-independent mapping** (one `UdpSocket` per
//! association, stable source port) with **address-restricted filtering** (a
//! return packet is relayed only if its source was a destination the client
//! already sent to). This is what lets client→server real-time traffic
//! (WebRTC to an SFU, game to a dedicated server) work while keeping the hop
//! from becoming an open UDP reflector. Full-cone / inbound-initiated P2P is
//! deliberately out of scope.
//!
//! There is **no fragmentation**: a UDP packet larger than the QUIC datagram
//! limit is dropped and counted. Real-time media targeted here is MTU-aware.
//! The relay is **un-throttled**, matching the reverse-hop TCP splice (rate 0).

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tracing::debug;

use super::frame::{self, Datagram};
use tokio::sync::OwnedSemaphorePermit;

/// Idle timeout after which the hop reclaims a UDP association's socket. Must
/// exceed common real-time keep-alives (WebRTC consent freshness is ~5 s) so an
/// active media flow is never torn down under it.
pub const UDP_SESSION_IDLE: Duration = Duration::from_secs(60);

/// How often the hop sweeps for idle associations.
pub const UDP_SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// Per-association cap on remembered destinations (address-restricted set).
/// Bounded so a client spraying many targets cannot grow hop memory without
/// limit; oldest entries are evicted first.
pub const MAX_CONTACTED_PER_SESSION: usize = 512;

/// Bounded return-packet queue per association; overflow drops the oldest,
/// which is correct for real-time UDP.
const RETURN_CHANNEL_CAP: usize = 1024;

/// Scratch buffer for one inbound UDP datagram (max UDP payload).
const RECV_BUF: usize = 65535;

/// A return packet observed on the hop egress socket: `(host, port, payload)`.
type ReturnPacket = (String, u16, Vec<u8>);

// ===========================================================================
// Edge side
// ===========================================================================

/// Per-hop-connection UDP demux state on the **edge**: routes hop→edge return
/// datagrams to the right association's [`UdpRelay`] channel, and hands out
/// unique per-connection `session_id`s.
#[derive(Default)]
pub struct EdgeUdpConn {
    sessions: Mutex<HashMap<u32, mpsc::Sender<ReturnPacket>>>,
    seq: AtomicU32,
}

impl EdgeUdpConn {
    /// Allocate a fresh non-zero session id for this connection.
    pub fn next_session_id(&self) -> u32 {
        loop {
            let v = self.seq.fetch_add(1, Ordering::Relaxed);
            if v != 0 {
                return v;
            }
        }
    }

    fn register(&self, sid: u32, tx: mpsc::Sender<ReturnPacket>) {
        self.sessions
            .lock()
            .expect("edge udp registry poisoned")
            .insert(sid, tx);
    }

    fn remove(&self, sid: u32) {
        self.sessions
            .lock()
            .expect("edge udp registry poisoned")
            .remove(&sid);
    }

    fn route(&self, dg: &Datagram) {
        let tx = {
            self.sessions
                .lock()
                .expect("edge udp registry poisoned")
                .get(&dg.session_id)
                .cloned()
        };
        if let Some(tx) = tx {
            // Drop on a full queue (real-time UDP): never block the demux.
            let _ = tx.try_send((dg.host.clone(), dg.port, dg.payload.to_vec()));
        }
    }
}

/// Spawn the edge-side per-connection datagram reader. Routes each hop→edge
/// datagram to its association channel and exits when the connection closes.
pub fn spawn_edge_demux(connection: quinn::Connection, state: Arc<EdgeUdpConn>) {
    tokio::spawn(async move {
        while let Ok(bytes) = connection.read_datagram().await {
            match frame::parse_datagram(&bytes) {
                Ok(dg) => state.route(&dg),
                Err(e) => debug!(error = %e, "reverse edge: dropping malformed datagram"),
            }
        }
    });
}

/// Egress handle returned by `outbound::connect_udp`. Sends client UDP packets
/// to the hop as datagrams and receives return packets. Un-throttled. Dropping
/// it deregisters the association and (by dropping the control stream) signals
/// the hop to reclaim the egress socket.
pub struct UdpRelay {
    connection: quinn::Connection,
    session_id: u32,
    conn_state: Arc<EdgeUdpConn>,
    rx: AsyncMutex<mpsc::Receiver<ReturnPacket>>,
    _control_send: quinn::SendStream,
    _control_recv: quinn::RecvStream,
    _permit: OwnedSemaphorePermit,
}

impl UdpRelay {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        connection: quinn::Connection,
        session_id: u32,
        conn_state: Arc<EdgeUdpConn>,
        rx: mpsc::Receiver<ReturnPacket>,
        control_send: quinn::SendStream,
        control_recv: quinn::RecvStream,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        UdpRelay {
            connection,
            session_id,
            conn_state,
            rx: AsyncMutex::new(rx),
            _control_send: control_send,
            _control_recv: control_recv,
            _permit: permit,
        }
    }

    /// Relay one client UDP packet to `host:port` via the hop. Oversized packets
    /// (beyond the QUIC datagram limit) and undeliverable domains are dropped —
    /// never fragmented — which is safe for the MTU-aware real-time targets.
    pub async fn send_to(&self, payload: &[u8], host: &str, port: u16) -> io::Result<()> {
        let Some(bytes) = frame::encode_datagram(self.session_id, host, port, payload) else {
            debug!(host, "reverse udp: undeliverable domain length, dropping");
            return Ok(());
        };
        if let Some(max) = self.connection.max_datagram_size() {
            if bytes.len() > max {
                debug!(
                    len = bytes.len(),
                    max, "reverse udp: oversize datagram dropped"
                );
                return Ok(());
            }
        }
        match self.connection.send_datagram(Bytes::from(bytes)) {
            Ok(()) => Ok(()),
            // Too large / transiently unsendable: drop, matching UDP semantics.
            Err(quinn::SendDatagramError::TooLarge) => Ok(()),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }

    /// Await the next return packet `(payload, host, port)` from the hop.
    pub async fn recv_from(&self) -> io::Result<(Vec<u8>, String, u16)> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some((host, port, payload)) => Ok((payload, host, port)),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "reverse udp relay closed",
            )),
        }
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.conn_state.remove(self.session_id);
    }
}

/// Register a freshly-associated session's return channel on the edge and build
/// the [`UdpRelay`]. Called by the edge manager after a successful `ASSOCIATE`.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_relay(
    connection: quinn::Connection,
    session_id: u32,
    conn_state: Arc<EdgeUdpConn>,
    control_send: quinn::SendStream,
    control_recv: quinn::RecvStream,
    permit: OwnedSemaphorePermit,
) -> UdpRelay {
    let (tx, rx) = mpsc::channel(RETURN_CHANNEL_CAP);
    conn_state.register(session_id, tx);
    UdpRelay::new(
        connection,
        session_id,
        conn_state,
        rx,
        control_send,
        control_recv,
        permit,
    )
}

// ===========================================================================
// Hop side
// ===========================================================================

/// Insertion-ordered bounded set of destinations the client has sent to, used
/// for address-restricted return filtering.
#[derive(Default)]
struct Contacted {
    order: VecDeque<SocketAddr>,
    set: HashSet<SocketAddr>,
}

impl Contacted {
    fn insert(&mut self, addr: SocketAddr) {
        if self.set.insert(addr) {
            self.order.push_back(addr);
            if self.order.len() > MAX_CONTACTED_PER_SESSION {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }

    fn contains(&self, addr: &SocketAddr) -> bool {
        self.set.contains(addr)
    }
}

/// One hop-side UDP association: its egress socket (EIM), the address-restricted
/// set, a resolution cache, and a last-activity timestamp for idle eviction.
struct HopUdpSession {
    socket: Arc<UdpSocket>,
    contacted: Mutex<Contacted>,
    resolve: Mutex<HashMap<String, SocketAddr>>,
    last_seen: Mutex<Instant>,
}

impl HopUdpSession {
    fn touch(&self) {
        *self.last_seen.lock().expect("last_seen poisoned") = Instant::now();
    }

    fn idle_for(&self) -> Duration {
        self.last_seen.lock().expect("last_seen poisoned").elapsed()
    }

    /// Resolve `host:port` to a single `SocketAddr`, caching the result for the
    /// association's lifetime so a per-packet flow does not re-resolve.
    async fn resolve(&self, host: &str, port: u16) -> Option<SocketAddr> {
        let key = format!("{host}:{port}");
        if let Some(addr) = self
            .resolve
            .lock()
            .expect("resolve cache poisoned")
            .get(&key)
        {
            return Some(*addr);
        }
        let addr = crate::resolver::resolve_one(host, port).await.ok()?;
        self.resolve
            .lock()
            .expect("resolve cache poisoned")
            .insert(key, addr);
        Some(addr)
    }
}

struct SessionEntry {
    session: Arc<HopUdpSession>,
    downlink: JoinHandle<()>,
}

impl Drop for SessionEntry {
    fn drop(&mut self) {
        self.downlink.abort();
    }
}

/// Per-hop-connection table of live UDP associations. Bounded by `max_sessions`;
/// insertion fails closed at capacity.
pub struct HopUdpTable {
    sessions: Mutex<HashMap<u32, SessionEntry>>,
    max_sessions: usize,
}

impl HopUdpTable {
    pub fn new(max_sessions: usize) -> Arc<Self> {
        Arc::new(HopUdpTable {
            sessions: Mutex::new(HashMap::new()),
            max_sessions: max_sessions.max(1),
        })
    }

    /// Allocate an egress socket for `session_id` and start its downlink task.
    /// Returns `false` (fail closed) if the connection is at UDP capacity or the
    /// socket cannot be bound.
    pub async fn associate(&self, session_id: u32, connection: quinn::Connection) -> bool {
        let socket = match UdpSocket::bind(("0.0.0.0", 0)).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                debug!(error = %e, "reverse hop: udp bind failed");
                return false;
            }
        };
        let session = Arc::new(HopUdpSession {
            socket,
            contacted: Mutex::new(Contacted::default()),
            resolve: Mutex::new(HashMap::new()),
            last_seen: Mutex::new(Instant::now()),
        });
        let downlink = spawn_downlink(session.clone(), connection, session_id);
        let entry = SessionEntry { session, downlink };

        let mut sessions = self.sessions.lock().expect("hop udp table poisoned");
        if sessions.len() >= self.max_sessions && !sessions.contains_key(&session_id) {
            return false; // fail closed; `entry` drop aborts the downlink task.
        }
        sessions.insert(session_id, entry);
        true
    }

    pub fn remove(&self, session_id: u32) {
        self.sessions
            .lock()
            .expect("hop udp table poisoned")
            .remove(&session_id);
    }

    fn get(&self, session_id: u32) -> Option<Arc<HopUdpSession>> {
        self.sessions
            .lock()
            .expect("hop udp table poisoned")
            .get(&session_id)
            .map(|e| e.session.clone())
    }

    fn evict_idle(&self) {
        self.sessions
            .lock()
            .expect("hop udp table poisoned")
            .retain(|_, e| e.session.idle_for() < UDP_SESSION_IDLE);
    }

    /// Handle one edge→hop datagram: resolve its per-packet destination, send it
    /// on the association's egress socket, and remember the destination so the
    /// reply is admitted by the address-restricted filter.
    async fn uplink(&self, bytes: &[u8]) {
        let dg = match frame::parse_datagram(bytes) {
            Ok(d) => d,
            Err(e) => {
                debug!(error = %e, "reverse hop: dropping malformed datagram");
                return;
            }
        };
        let Some(session) = self.get(dg.session_id) else {
            return; // unknown session: fail closed (drop)
        };
        session.touch();
        let Some(addr) = session.resolve(&dg.host, dg.port).await else {
            return;
        };
        if session.socket.send_to(dg.payload, addr).await.is_ok() {
            session
                .contacted
                .lock()
                .expect("contacted poisoned")
                .insert(addr);
        }
    }
}

/// The per-association downlink: read replies off the egress socket, drop any
/// whose source was not contacted (address-restricted), and relay the rest back
/// to the edge as datagrams tagged with `session_id`.
fn spawn_downlink(
    session: Arc<HopUdpSession>,
    connection: quinn::Connection,
    session_id: u32,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            let (n, src) = match session.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if !session
                .contacted
                .lock()
                .expect("contacted poisoned")
                .contains(&src)
            {
                continue; // address-restricted: never relay an uninvited source
            }
            session.touch();
            let host = src.ip().to_string();
            let Some(bytes) = frame::encode_datagram(session_id, &host, src.port(), &buf[..n])
            else {
                continue;
            };
            if let Some(max) = connection.max_datagram_size() {
                if bytes.len() > max {
                    continue; // no fragmentation
                }
            }
            let _ = connection.send_datagram(Bytes::from(bytes));
        }
    })
}

/// Spawn the hop-side per-connection datagram reader (uplink) plus an idle
/// sweeper. Both exit when the connection closes.
pub fn spawn_hop_demux(connection: quinn::Connection, table: Arc<HopUdpTable>) {
    let sweeper_table = table.clone();
    let sweeper = tokio::spawn(async move {
        let mut tick = tokio::time::interval(UDP_SWEEP_INTERVAL);
        loop {
            tick.tick().await;
            sweeper_table.evict_idle();
        }
    });
    tokio::spawn(async move {
        while let Ok(bytes) = connection.read_datagram().await {
            table.uplink(&bytes).await;
        }
        sweeper.abort();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contacted_is_bounded_and_membership_correct() {
        let mut c = Contacted::default();
        let base: SocketAddr = "10.0.0.1:1".parse().unwrap();
        c.insert(base);
        assert!(c.contains(&base));
        // Overflow evicts the oldest.
        for p in 0..(MAX_CONTACTED_PER_SESSION as u16 + 5) {
            c.insert(format!("10.0.0.2:{}", p + 1).parse().unwrap());
        }
        assert!(c.set.len() <= MAX_CONTACTED_PER_SESSION);
        assert!(!c.contains(&base)); // evicted
    }

    #[test]
    fn next_session_id_is_nonzero_and_monotonic() {
        let c = EdgeUdpConn::default();
        let a = c.next_session_id();
        let b = c.next_session_id();
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(a, b);
    }
}
