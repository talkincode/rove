//! Userspace TCP over the subnetra overlay.
//!
//! smoltcp gives us a synchronous, poll-driven IPv4/TCP stack; this module wraps
//! it in a single Tokio [`Driver`] task and exposes ordinary async streams so the
//! rest of Rove never sees smoltcp:
//!
//! * **hub inbound** — the driver keeps a small pool of listening sockets on the
//!   node's overlay IP + a proxy port; each accepted connection is surfaced as a
//!   [`SubnetraStream`] on the `accept` channel and handed to Rove's HTTP/SOCKS
//!   dispatch.
//! * **spoke egress** — [`NetHandle::connect`] opens a TCP connection to an
//!   overlay destination and returns a [`SubnetraStream`], which Rove's outbound
//!   layer uses like any other upstream.
//!
//! [`SubnetraStream`] implements [`AsyncRead`]/[`AsyncWrite`], so it satisfies
//! Rove's `IoStream` and drops straight into the existing splice/proxy machinery.
//!
//! # Concurrency model
//!
//! The driver owns the [`Interface`], the [`SocketSet`], and the
//! [`ChannelDevice`] on one task — smoltcp is not `Sync`, and this keeps all of
//! its state single-threaded. Streams talk to the driver through per-connection
//! shared buffers guarded by a `Mutex`, plus a shared [`Notify`] that wakes the
//! driver whenever an app-side read frees window space or a write enqueues data.

mod device;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, info, warn};

use self::device::ChannelDevice;
use super::reactor::DataPlaneHandle;

/// Per-socket smoltcp send/receive buffer.
const SOCKET_BUF: usize = 64 * 1024;
/// Cap on bytes buffered net→app and app→net before applying backpressure.
const CONN_BUF_CAP: usize = 256 * 1024;
/// Number of sockets kept in the `Listen` state, ready to absorb concurrent
/// SYNs. The pool is topped back up on every service pass (see
/// [`Driver::top_up_listeners`]), so this is spare capacity, not a hard cap on
/// concurrent handshakes.
const LISTEN_BACKLOG: usize = 8;
/// Hard cap on the whole listener pool (spare `Listen` sockets plus in-flight
/// `SynReceived` handshakes), bounding the memory a SYN burst from an
/// authenticated peer can pin. Bursts beyond this are answered with RST, like
/// overflowing a kernel accept backlog.
const MAX_LISTEN_SOCKETS: usize = 128;
/// Safety cap on poll/service iterations per wake, so a busy socket can never
/// spin the driver forever.
const MAX_PUMP_ITERS: usize = 16;

/// Shared per-connection state between a [`SubnetraStream`] and the driver.
struct ConnShared {
    /// Bytes received from the overlay, waiting for the app to read.
    rx: VecDeque<u8>,
    /// Bytes written by the app, waiting to be pushed into smoltcp.
    tx: VecDeque<u8>,
    /// The app called `shutdown()`: send a FIN once `tx` has drained.
    app_shutdown: bool,
    /// The peer closed its half (FIN) — no more `rx` will ever arrive.
    net_closed: bool,
    /// The connection was reset/aborted; reads and writes should error.
    aborted: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

impl ConnShared {
    fn new() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            app_shutdown: false,
            net_closed: false,
            aborted: false,
            read_waker: None,
            write_waker: None,
        }
    }

    fn wake_reader(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
    }

    fn wake_writer(&mut self) {
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }
}

/// An async TCP stream carried over the subnetra overlay. Satisfies Rove's
/// `IoStream` (it is `AsyncRead + AsyncWrite + Unpin + Send`).
pub struct SubnetraStream {
    shared: Arc<Mutex<ConnShared>>,
    notify: Arc<Notify>,
    peer: SocketAddr,
}

impl SubnetraStream {
    /// The overlay endpoint at the other end (for access logging).
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }
}

impl AsyncRead for SubnetraStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.shared.lock().unwrap();
        if !g.rx.is_empty() {
            let n = buf.remaining().min(g.rx.len());
            for _ in 0..n {
                buf.put_slice(&[g.rx.pop_front().unwrap()]);
            }
            drop(g);
            // Reading freed window space; let the driver advance the window.
            self.notify.notify_one();
            return Poll::Ready(Ok(()));
        }
        if g.aborted {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "subnetra connection reset",
            )));
        }
        if g.net_closed {
            return Poll::Ready(Ok(())); // clean EOF
        }
        g.read_waker = Some(cx.waker().clone());
        drop(g);
        self.notify.notify_one();
        Poll::Pending
    }
}

impl AsyncWrite for SubnetraStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.shared.lock().unwrap();
        if g.aborted {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "subnetra connection reset",
            )));
        }
        if g.app_shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            )));
        }
        let space = CONN_BUF_CAP.saturating_sub(g.tx.len());
        if space == 0 {
            g.write_waker = Some(cx.waker().clone());
            drop(g);
            self.notify.notify_one();
            return Poll::Pending;
        }
        let n = data.len().min(space);
        g.tx.extend(&data[..n]);
        drop(g);
        self.notify.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut g = self.shared.lock().unwrap();
        if g.aborted {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "subnetra connection reset",
            )));
        }
        if g.tx.is_empty() {
            return Poll::Ready(Ok(()));
        }
        g.write_waker = Some(cx.waker().clone());
        drop(g);
        self.notify.notify_one();
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut g = self.shared.lock().unwrap();
        if g.aborted || g.net_closed && g.tx.is_empty() {
            g.app_shutdown = true;
            drop(g);
            self.notify.notify_one();
            return Poll::Ready(Ok(()));
        }
        // Flush pending data before signalling FIN.
        if !g.tx.is_empty() {
            g.write_waker = Some(cx.waker().clone());
            drop(g);
            self.notify.notify_one();
            return Poll::Pending;
        }
        g.app_shutdown = true;
        drop(g);
        self.notify.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for SubnetraStream {
    fn drop(&mut self) {
        // Ensure the driver tears the socket down (FIN) when the app drops us.
        if let Ok(mut g) = self.shared.lock() {
            g.app_shutdown = true;
        }
        self.notify.notify_one();
    }
}

/// A request from a [`NetHandle`] to the driver.
enum Command {
    Connect {
        dst: Ipv4Addr,
        port: u16,
        respond: oneshot::Sender<io::Result<SubnetraStream>>,
    },
}

/// Handle to originate overlay connections (spoke egress).
#[derive(Clone)]
pub struct NetHandle {
    cmd_tx: mpsc::Sender<Command>,
    overlay_ip: Ipv4Addr,
}

impl NetHandle {
    /// Open a TCP connection to an overlay destination, returning an async stream.
    pub async fn connect(&self, dst: Ipv4Addr, port: u16) -> io::Result<SubnetraStream> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Connect {
                dst,
                port,
                respond: tx,
            })
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::NotConnected, "subnetra netstack stopped")
            })?;
        rx.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "subnetra netstack dropped request",
            )
        })?
    }

    pub fn overlay_ip(&self) -> Ipv4Addr {
        self.overlay_ip
    }
}

/// Spawn the userspace IP stack over a data-plane handle.
///
/// * `dp` / `inbound` — the reactor handle (tx) and the mesh→local inner-packet
///   stream (rx) from [`super::reactor::spawn`].
/// * `listen_port` — `Some(port)` makes this a hub that accepts overlay TCP on
///   `overlay_ip:port`; `None` is egress-only (spoke).
///
/// Returns the connect handle and, for a hub, the stream of accepted connections.
pub fn spawn(
    dp: DataPlaneHandle,
    inbound: mpsc::Receiver<Vec<u8>>,
    overlay_ip: Ipv4Addr,
    overlay_prefix: u8,
    listen_port: Option<u16>,
    mtu: usize,
) -> (NetHandle, mpsc::Receiver<(SubnetraStream, SocketAddr)>) {
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (accept_tx, accept_rx) = mpsc::channel(64);

    let handle = NetHandle { cmd_tx, overlay_ip };

    let driver = Driver::new(
        dp,
        overlay_ip,
        overlay_prefix,
        listen_port,
        cmd_rx,
        accept_tx,
        mtu,
    );
    tokio::spawn(driver.run(inbound));

    (handle, accept_rx)
}

struct Conn {
    shared: Arc<Mutex<ConnShared>>,
}

struct Driver {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: ChannelDevice,
    dp: DataPlaneHandle,
    notify: Arc<Notify>,
    cmd_rx: mpsc::Receiver<Command>,
    accept_tx: mpsc::Sender<(SubnetraStream, SocketAddr)>,
    listen_port: Option<u16>,
    listeners: HashSet<SocketHandle>,
    conns: HashMap<SocketHandle, Conn>,
    pending_connects: HashMap<SocketHandle, oneshot::Sender<io::Result<SubnetraStream>>>,
    next_port: u16,
}

impl Driver {
    #[allow(clippy::too_many_arguments)]
    fn new(
        dp: DataPlaneHandle,
        overlay_ip: Ipv4Addr,
        overlay_prefix: u8,
        listen_port: Option<u16>,
        cmd_rx: mpsc::Receiver<Command>,
        accept_tx: mpsc::Sender<(SubnetraStream, SocketAddr)>,
        mtu: usize,
    ) -> Self {
        let mut device = ChannelDevice::with_mtu(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = random_seed();
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        let o = overlay_ip.octets();
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(
                IpAddress::v4(o[0], o[1], o[2], o[3]),
                overlay_prefix,
            ));
        });

        Self {
            iface,
            sockets: SocketSet::new(Vec::new()),
            device,
            dp,
            notify: Arc::new(Notify::new()),
            cmd_rx,
            accept_tx,
            listen_port,
            listeners: HashSet::new(),
            conns: HashMap::new(),
            pending_connects: HashMap::new(),
            next_port: 49152,
        }
    }

    async fn run(mut self, mut inbound: mpsc::Receiver<Vec<u8>>) {
        if let Some(port) = self.listen_port {
            for _ in 0..LISTEN_BACKLOG {
                self.add_listener(port);
            }
            info!(port, "subnetra netstack listening on overlay");
        }
        let notify = self.notify.clone();
        // Once the last NetHandle drops, `cmd_rx` closes; we stop taking new
        // connects but keep servicing established streams and (hub) accepts. The
        // driver only exits when the reactor's inbound channel closes.
        let mut cmd_open = true;

        loop {
            self.pump();

            let delay = self
                .iface
                .poll_delay(SmolInstant::now(), &self.sockets)
                .map(|d| tokio::time::Duration::from_micros(d.total_micros()));

            tokio::select! {
                cmd = self.cmd_rx.recv(), if cmd_open => {
                    match cmd {
                        Some(cmd) => self.handle_command(cmd),
                        None => cmd_open = false,
                    }
                }
                pkt = inbound.recv() => {
                    match pkt {
                        Some(pkt) => self.device.push_rx(pkt),
                        None => {
                            info!("subnetra netstack: mesh channel closed, exiting");
                            return;
                        }
                    }
                }
                _ = notify.notified() => {}
                _ = sleep_opt(delay) => {}
            }
        }
    }

    /// Drive smoltcp to a fixpoint: poll, forward emitted packets to the mesh,
    /// then move bytes between smoltcp and the app buffers, repeating while there
    /// is still work (bounded by [`MAX_PUMP_ITERS`]).
    fn pump(&mut self) {
        for _ in 0..MAX_PUMP_ITERS {
            let now = SmolInstant::now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);

            let emitted = self.device.drain_tx();
            let did_emit = !emitted.is_empty();
            for pkt in emitted {
                self.dp.try_send_inner(pkt);
            }

            let enqueued = self.service();
            if !did_emit && !enqueued && !self.device.has_rx() {
                break;
            }
        }
    }

    /// Reconcile socket state with the app buffers. Returns `true` if anything was
    /// enqueued into a smoltcp send buffer (so the caller should re-poll to emit).
    fn service(&mut self) -> bool {
        self.promote_listeners();
        self.top_up_listeners();
        self.resolve_connects();
        self.service_conns()
    }

    /// A listening socket that has completed its handshake has accepted a
    /// connection; surface it and replenish the backlog. Sockets still in the
    /// `Listen`/`SynReceived` handshake are left alone (promoting at `SynReceived`
    /// would trip the `!may_recv` EOF check below before the peer can send).
    fn promote_listeners(&mut self) {
        let mut ready = Vec::new();
        let mut dead = Vec::new();
        for &h in &self.listeners {
            match self.sockets.get::<tcp::Socket>(h).state() {
                tcp::State::Listen | tcp::State::SynReceived => {}
                tcp::State::Closed => dead.push(h),
                _ => ready.push(h),
            }
        }

        for h in dead {
            self.listeners.remove(&h);
            self.sockets.remove(h);
        }

        for h in ready {
            self.listeners.remove(&h);
            let peer = remote_addr(self.sockets.get::<tcp::Socket>(h));
            let shared = Arc::new(Mutex::new(ConnShared::new()));
            let stream = SubnetraStream {
                shared: shared.clone(),
                notify: self.notify.clone(),
                peer,
            };
            self.conns.insert(h, Conn { shared });
            if self.accept_tx.try_send((stream, peer)).is_err() {
                // No one is accepting (or backlog full): reset the connection
                // rather than leave it half-open.
                self.sockets.get_mut::<tcp::Socket>(h).abort();
                self.conns.remove(&h);
                debug!(%peer, "subnetra: dropped inbound conn, no accept capacity");
            }
        }
    }

    /// Keep [`LISTEN_BACKLOG`] sockets in the `Listen` state at all times.
    ///
    /// A socket mid-handshake (`SynReceived`) can no longer absorb a new SYN, so
    /// replenishing only when a handshake completes (as promotion once did) left
    /// a window where a SYN burst wider than the backlog found no listener and
    /// was answered with RST — concurrent overlay connects beyond 8 failed. The
    /// driver ingests one inbound datagram per pump, so topping the pool up here
    /// guarantees the next SYN always finds a listener while the pool is under
    /// [`MAX_LISTEN_SOCKETS`].
    fn top_up_listeners(&mut self) {
        let Some(port) = self.listen_port else {
            return;
        };
        let mut spare = self
            .listeners
            .iter()
            .filter(|&&h| {
                matches!(
                    self.sockets.get::<tcp::Socket>(h).state(),
                    tcp::State::Listen
                )
            })
            .count();
        while spare < LISTEN_BACKLOG && self.listeners.len() < MAX_LISTEN_SOCKETS {
            if !self.add_listener(port) {
                break;
            }
            spare += 1;
        }
    }

    /// Complete or fail any pending spoke connects that have resolved.
    fn resolve_connects(&mut self) {
        let resolved: Vec<(SocketHandle, bool)> = self
            .pending_connects
            .keys()
            .copied()
            .filter_map(|h| match self.sockets.get::<tcp::Socket>(h).state() {
                tcp::State::Established => Some((h, true)),
                tcp::State::Closed => Some((h, false)),
                _ => None,
            })
            .collect();

        for (h, ok) in resolved {
            let responder = self.pending_connects.remove(&h).unwrap();
            if ok {
                let peer = remote_addr(self.sockets.get::<tcp::Socket>(h));
                let shared = Arc::new(Mutex::new(ConnShared::new()));
                let stream = SubnetraStream {
                    shared: shared.clone(),
                    notify: self.notify.clone(),
                    peer,
                };
                self.conns.insert(h, Conn { shared });
                let _ = responder.send(Ok(stream));
            } else {
                self.sockets.remove(h);
                let _ = responder.send(Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "subnetra connect failed",
                )));
            }
        }
    }

    /// Pump bytes for every established connection and reap dead ones.
    fn service_conns(&mut self) -> bool {
        let mut enqueued = false;
        let items: Vec<(SocketHandle, Arc<Mutex<ConnShared>>)> = self
            .conns
            .iter()
            .map(|(h, c)| (*h, c.shared.clone()))
            .collect();

        let mut dead = Vec::new();
        for (h, shared) in items {
            let sock = self.sockets.get_mut::<tcp::Socket>(h);
            let mut g = shared.lock().unwrap();

            // net -> app: copy received bytes into the app read buffer.
            let mut got = false;
            while sock.can_recv() && g.rx.len() < CONN_BUF_CAP {
                let cap = CONN_BUF_CAP - g.rx.len();
                let mut moved = 0usize;
                let res = sock.recv(|data| {
                    let take = data.len().min(cap);
                    g.rx.extend(&data[..take]);
                    moved = take;
                    (take, ())
                });
                if res.is_err() || moved == 0 {
                    break;
                }
                got = true;
            }
            if got {
                g.wake_reader();
            }

            // app -> net
            while sock.can_send() && !g.tx.is_empty() {
                let n = {
                    let slice = g.tx.make_contiguous();
                    sock.send_slice(slice).unwrap_or(0)
                };
                if n == 0 {
                    break;
                }
                g.tx.drain(..n);
                enqueued = true;
                g.wake_writer();
            }

            // app requested shutdown and everything is flushed: send FIN.
            if g.app_shutdown && g.tx.is_empty() && sock.may_send() {
                sock.close();
            }

            // peer closed its send half
            if !sock.may_recv() && !g.net_closed {
                g.net_closed = true;
                g.wake_reader();
            }

            if matches!(sock.state(), tcp::State::Closed) {
                g.net_closed = true;
                g.wake_reader();
                g.wake_writer();
                dead.push(h);
            } else if matches!(sock.state(), tcp::State::TimeWait) && !sock.can_recv() {
                // Both FINs are exchanged and every byte has been handed to the
                // app buffer: the connection is over for the app, so evict it now
                // instead of holding smoltcp's 10s TIME_WAIT. Keeping thousands
                // of TIME_WAIT sockets after a connection churn made every pump
                // O(all sockets) and collapsed bulk throughput. The classic
                // TIME_WAIT hazard (old duplicates hitting a reused 4-tuple)
                // needs the ephemeral allocator to lap its 16384-port cycle
                // within segment lifetime, and a stray retransmitted FIN just
                // draws a harmless RST.
                g.net_closed = true;
                g.wake_reader();
                g.wake_writer();
                dead.push(h);
            }
        }

        for h in dead {
            self.conns.remove(&h);
            self.sockets.remove(h);
        }
        enqueued
    }

    fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::Connect { dst, port, respond } => self.connect(dst, port, respond),
        }
    }

    fn connect(
        &mut self,
        dst: Ipv4Addr,
        port: u16,
        respond: oneshot::Sender<io::Result<SubnetraStream>>,
    ) {
        let rx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
        let tx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
        let mut sock = tcp::Socket::new(rx, tx);
        let local_port = self.next_ephemeral();
        let d = dst.octets();
        let remote = IpEndpoint::new(IpAddress::v4(d[0], d[1], d[2], d[3]), port);
        let result = sock.connect(self.iface.context(), remote, local_port);
        match result {
            Ok(()) => {
                let h = self.sockets.add(sock);
                self.pending_connects.insert(h, respond);
                self.notify.notify_one();
            }
            Err(e) => {
                let _ = respond.send(Err(io::Error::other(format!(
                    "subnetra connect setup failed: {e}"
                ))));
            }
        }
    }

    fn add_listener(&mut self, port: u16) -> bool {
        let rx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
        let tx = tcp::SocketBuffer::new(vec![0u8; SOCKET_BUF]);
        let mut sock = tcp::Socket::new(rx, tx);
        if let Err(e) = sock.listen(port) {
            warn!(port, "subnetra: failed to open listener: {e}");
            return false;
        }
        let h = self.sockets.add(sock);
        self.listeners.insert(h);
        true
    }

    fn next_ephemeral(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = if self.next_port == u16::MAX {
            49152
        } else {
            self.next_port + 1
        };
        p
    }
}

/// Convert smoltcp's remote endpoint to a std `SocketAddr` for logging. In
/// smoltcp 0.12 an `IpAddress::Ipv4` already wraps a std `Ipv4Addr`.
fn remote_addr(sock: &tcp::Socket) -> SocketAddr {
    match sock.remote_endpoint() {
        Some(IpEndpoint {
            addr: IpAddress::Ipv4(v4),
            port,
        }) => SocketAddr::V4(SocketAddrV4::new(v4, port)),
        _ => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
    }
}

async fn sleep_opt(delay: Option<tokio::time::Duration>) {
    match delay {
        Some(d) => tokio::time::sleep(d).await,
        // No timer pending: park until an external event wakes the select.
        None => std::future::pending::<()>().await,
    }
}

fn random_seed() -> u64 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    u64::from_le_bytes(b)
}
