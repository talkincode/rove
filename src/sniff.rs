//! Bounded classification of initial TCP payload bytes.

use rustls::server::Acceptor;
use std::io::Cursor;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use url::{Host as UrlHost, Url};

/// Absolute allocation/read ceiling for one classification attempt.
pub const HARD_MAX_SNIFF_BYTES: usize = 64 * 1024;
/// Conservative per-connection default; callers may choose a lower soft limit.
pub const DEFAULT_MAX_SNIFF_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffProtocol {
    Tls,
    Http,
}

impl SniffProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            SniffProtocol::Tls => "tls",
            SniffProtocol::Http => "http",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffedHost {
    pub protocol: SniffProtocol,
    pub host: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffResult {
    Matched(SniffedHost),
    NeedMore,
    Unsupported,
    Malformed,
    LimitExceeded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniffOutcome {
    Matched,
    Unsupported,
    Timeout,
    Malformed,
    LimitExceeded,
    Incomplete,
}

impl SniffOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            SniffOutcome::Matched => "matched",
            SniffOutcome::Unsupported => "unsupported",
            SniffOutcome::Timeout => "timeout",
            SniffOutcome::Malformed => "malformed",
            SniffOutcome::LimitExceeded => "limit_exceeded",
            SniffOutcome::Incomplete => "incomplete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniffObservation {
    pub outcome: SniffOutcome,
    pub protocol: Option<SniffProtocol>,
    pub host: Option<String>,
}

impl SniffObservation {
    fn terminal(outcome: SniffOutcome) -> Self {
        SniffObservation {
            outcome,
            protocol: None,
            host: None,
        }
    }

    fn matched(value: SniffedHost) -> Self {
        SniffObservation {
            outcome: SniffOutcome::Matched,
            protocol: Some(value.protocol),
            host: Some(value.host),
        }
    }
}

struct ObserveState {
    parser: ObserveParser,
    prefix: Vec<u8>,
    observed_bytes: usize,
    max_bytes: usize,
    started: Instant,
    timeout: Duration,
    observation: Option<SniffObservation>,
    done: Arc<tokio::sync::Notify>,
}

enum ObserveParser {
    Undecided,
    Tls(Box<Acceptor>),
    Http { scan_from: usize },
    Done,
}

impl ObserveState {
    fn new(max_bytes: usize, timeout: Duration, done: Arc<tokio::sync::Notify>) -> Self {
        let max_bytes = max_bytes.min(HARD_MAX_SNIFF_BYTES);
        ObserveState {
            parser: ObserveParser::Undecided,
            prefix: Vec::new(),
            observed_bytes: 0,
            max_bytes,
            started: Instant::now(),
            timeout,
            observation: None,
            done,
        }
    }

    fn observe(&mut self, bytes: &[u8]) {
        if self.observation.is_some() {
            return;
        }
        if self.started.elapsed() >= self.timeout {
            self.finish_timeout();
            return;
        }

        let remaining = self.max_bytes.saturating_sub(self.observed_bytes);
        let take = bytes.len().min(remaining);
        let captured = &bytes[..take];
        self.observed_bytes += take;

        if matches!(self.parser, ObserveParser::Undecided) {
            self.parser = match captured.first() {
                Some(0x16) => ObserveParser::Tls(Box::default()),
                Some(_) if could_be_http(captured) => ObserveParser::Http { scan_from: 0 },
                Some(_) => {
                    self.finish(SniffObservation::terminal(SniffOutcome::Unsupported));
                    return;
                }
                None => ObserveParser::Undecided,
            };
        }

        let observation = match &mut self.parser {
            ObserveParser::Tls(acceptor) => observe_tls_incremental(acceptor, captured),
            ObserveParser::Http { scan_from } => {
                observe_http_incremental(&mut self.prefix, scan_from, captured)
            }
            ObserveParser::Undecided | ObserveParser::Done => None,
        };
        if let Some(observation) = observation {
            self.finish(observation);
        } else if take < bytes.len() || self.observed_bytes >= self.max_bytes {
            self.finish(SniffObservation::terminal(SniffOutcome::LimitExceeded));
        }
    }

    fn finish_timeout(&mut self) {
        if self.observation.is_none() {
            self.finish(SniffObservation::terminal(SniffOutcome::Timeout));
        }
    }

    fn finish_stream(&mut self) {
        if self.observation.is_some() {
            return;
        }
        let outcome = if self.started.elapsed() >= self.timeout {
            SniffOutcome::Timeout
        } else {
            SniffOutcome::Incomplete
        };
        self.finish(SniffObservation::terminal(outcome));
    }

    fn snapshot(&mut self) -> SniffObservation {
        if self.observation.is_none() {
            let outcome = if self.started.elapsed() >= self.timeout {
                SniffOutcome::Timeout
            } else {
                SniffOutcome::Incomplete
            };
            self.finish(SniffObservation::terminal(outcome));
        }
        self.observation
            .as_ref()
            .expect("observation finalized")
            .clone()
    }

    fn finish(&mut self, observation: SniffObservation) {
        self.observation = Some(observation);
        self.parser = ObserveParser::Done;
        self.prefix = Vec::new();
        self.done.notify_one();
    }
}

fn observe_tls_incremental(acceptor: &mut Acceptor, bytes: &[u8]) -> Option<SniffObservation> {
    let mut reader = Cursor::new(bytes);
    loop {
        let read = match acceptor.read_tls(&mut reader) {
            Ok(read) => read,
            Err(_) => {
                return Some(SniffObservation::terminal(SniffOutcome::Malformed));
            }
        };
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                return Some(match accepted.client_hello().server_name() {
                    Some(host) => match normalize_dns_name(host) {
                        Some(host) => SniffObservation::matched(SniffedHost {
                            protocol: SniffProtocol::Tls,
                            host,
                        }),
                        None => SniffObservation::terminal(SniffOutcome::Malformed),
                    },
                    None => SniffObservation::terminal(SniffOutcome::Unsupported),
                });
            }
            Ok(None) if read == 0 => return None,
            Ok(None) => {}
            Err(_) => return Some(SniffObservation::terminal(SniffOutcome::Malformed)),
        }
    }
}

fn observe_http_incremental(
    prefix: &mut Vec<u8>,
    scan_from: &mut usize,
    bytes: &[u8],
) -> Option<SniffObservation> {
    prefix.extend_from_slice(bytes);
    let start = scan_from.saturating_sub(3);
    let Some(relative) = crate::util::find_sub(&prefix[start..], b"\r\n\r\n") else {
        *scan_from = prefix.len();
        return None;
    };
    let end = start + relative + 4;
    Some(match classify_http(&prefix[..end]) {
        SniffResult::Matched(value) => SniffObservation::matched(value),
        SniffResult::Unsupported => SniffObservation::terminal(SniffOutcome::Unsupported),
        SniffResult::Malformed | SniffResult::NeedMore | SniffResult::LimitExceeded => {
            SniffObservation::terminal(SniffOutcome::Malformed)
        }
    })
}

#[derive(Clone)]
pub struct SniffHandle {
    state: Arc<Mutex<ObserveState>>,
}

impl SniffHandle {
    pub fn observation(&self) -> SniffObservation {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot()
    }
}

pub struct SniffingIo<S> {
    inner: S,
    state: Arc<Mutex<ObserveState>>,
}

impl<S> SniffingIo<S> {
    pub fn new(inner: S, max_bytes: usize, timeout: Duration) -> (Self, SniffHandle) {
        let done = Arc::new(tokio::sync::Notify::new());
        let state = Arc::new(Mutex::new(ObserveState::new(
            max_bytes,
            timeout,
            done.clone(),
        )));
        let handle = SniffHandle {
            state: state.clone(),
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak_state = Arc::downgrade(&state);
            runtime.spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(timeout) => {
                        if let Some(state) = weak_state.upgrade() {
                            state
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .finish_timeout();
                        }
                    }
                    _ = done.notified() => {}
                }
            });
        }
        (SniffingIo { inner, state }, handle)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SniffingIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let filled_before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let filled_after = buf.filled().len();
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if filled_after == filled_before {
                    state.finish_stream();
                } else {
                    state.observe(&buf.filled()[filled_before..filled_after]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .finish_stream();
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SniffingIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPrefix {
    pub bytes: Vec<u8>,
    pub observation: SniffObservation,
}

pub async fn capture_prefix<R>(
    reader: &mut R,
    max_bytes: usize,
    timeout: Duration,
) -> std::io::Result<CapturedPrefix>
where
    R: AsyncRead + Unpin,
{
    let max_bytes = max_bytes.min(HARD_MAX_SNIFF_BYTES);
    let done = Arc::new(tokio::sync::Notify::new());
    let mut state = ObserveState::new(max_bytes, timeout, done);
    let mut bytes = Vec::with_capacity(max_bytes.min(2048));
    let mut chunk = vec![0u8; max_bytes.clamp(1, 2048)];
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    while state.observation.is_none() {
        let remaining = max_bytes.saturating_sub(bytes.len());
        if remaining == 0 {
            state.observe(&[]);
            break;
        }
        let read_len = remaining.min(chunk.len());
        tokio::select! {
            biased;
            _ = &mut deadline => {
                state.finish_timeout();
                break;
            }
            read = reader.read(&mut chunk[..read_len]) => {
                let read = read?;
                if read == 0 {
                    state.finish_stream();
                    break;
                }
                bytes.extend_from_slice(&chunk[..read]);
                state.observe(&chunk[..read]);
            }
        }
    }

    Ok(CapturedPrefix {
        bytes,
        observation: state.snapshot(),
    })
}

/// Classify a buffered TCP prefix without retaining any payload beyond the call.
pub fn classify_prefix(prefix: &[u8], max_bytes: usize) -> SniffResult {
    let limit = max_bytes.min(HARD_MAX_SNIFF_BYTES);
    if prefix.len() > limit {
        return SniffResult::LimitExceeded;
    }

    let result = match prefix.first() {
        None => SniffResult::NeedMore,
        Some(0x16) => classify_tls(prefix),
        Some(_) if could_be_http(prefix) => classify_http(prefix),
        Some(_) => SniffResult::Unsupported,
    };

    if result == SniffResult::NeedMore && prefix.len() >= limit {
        SniffResult::LimitExceeded
    } else {
        result
    }
}

fn classify_tls(prefix: &[u8]) -> SniffResult {
    let mut acceptor = Acceptor::default();
    let mut reader = Cursor::new(prefix);
    loop {
        let read = match acceptor.read_tls(&mut reader) {
            Ok(read) => read,
            Err(_) => return SniffResult::Malformed,
        };
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                return match accepted.client_hello().server_name() {
                    Some(host) => match normalize_dns_name(host) {
                        Some(host) => matched(SniffProtocol::Tls, host),
                        None => SniffResult::Malformed,
                    },
                    None => SniffResult::Unsupported,
                };
            }
            Ok(None) if read == 0 => return SniffResult::NeedMore,
            Ok(None) => {}
            Err(_) => return SniffResult::Malformed,
        }
    }
}

fn could_be_http(mut prefix: &[u8]) -> bool {
    while prefix.starts_with(b"\r\n") {
        prefix = &prefix[2..];
    }
    if prefix.is_empty() || prefix == b"\r" {
        return true;
    }
    is_http_token_byte(prefix[0])
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
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
}

fn classify_http(prefix: &[u8]) -> SniffResult {
    const MAX_HEADERS: usize = 64;

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(prefix) {
        Ok(httparse::Status::Partial) => SniffResult::NeedMore,
        Err(_) => SniffResult::Malformed,
        Ok(httparse::Status::Complete(_)) => {
            let host = match http_request_host(&request) {
                Ok(host) => host,
                Err(()) => return SniffResult::Malformed,
            };
            match host {
                Some(host) => matched(SniffProtocol::Http, host),
                None => SniffResult::Unsupported,
            }
        }
    }
}

fn http_request_host(request: &httparse::Request<'_, '_>) -> Result<Option<String>, ()> {
    let header_host = unique_http_host(request.headers)?;
    let method = request.method.ok_or(())?;
    let target = request.path.ok_or(())?;

    if method.eq_ignore_ascii_case("CONNECT") {
        return normalize_connect_authority(target).map(Some).ok_or(());
    }
    if target.starts_with("http://") || target.starts_with("https://") {
        return normalize_absolute_http_target(target).map(Some).ok_or(());
    }
    if target == "*" || target.starts_with('/') {
        return Ok(header_host);
    }
    Err(())
}

fn unique_http_host(headers: &[httparse::Header<'_>]) -> Result<Option<String>, ()> {
    let mut host = None;
    for header in headers {
        if !header.name.eq_ignore_ascii_case("host") {
            continue;
        }
        if host.is_some() {
            return Err(());
        }
        let value = std::str::from_utf8(header.value).map_err(|_| ())?;
        host = Some(normalize_http_authority(value).ok_or(())?);
    }
    Ok(host)
}

fn normalize_connect_authority(authority: &str) -> Option<String> {
    (authority.matches(':').count() == 1)
        .then(|| normalize_http_authority(authority))
        .flatten()
}

fn normalize_absolute_http_target(target: &str) -> Option<String> {
    let url = Url::parse(target).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    match url.host()? {
        UrlHost::Domain(host) => normalize_dns_name(host),
        UrlHost::Ipv4(_) | UrlHost::Ipv6(_) => None,
    }
}

fn normalize_http_authority(authority: &str) -> Option<String> {
    let authority = authority.trim();
    if authority.is_empty()
        || authority.starts_with('[')
        || authority.contains(['@', '/', '\\'])
        || authority.bytes().any(|b| b.is_ascii_whitespace())
    {
        return None;
    }

    let host = match authority.matches(':').count() {
        0 => authority,
        1 => {
            let (host, port) = authority.rsplit_once(':')?;
            let port = port.parse::<u16>().ok()?;
            if port == 0 {
                return None;
            }
            host
        }
        _ => return None,
    };
    normalize_dns_name(host)
}

/// Normalize an exact DNS name accepted both from a TLS ClientHello and from
/// server-side listener configuration. IP literals, wildcard forms, URLs and
/// malformed labels deliberately have no representation here.
pub(crate) fn normalize_dns_name(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.parse::<IpAddr>().is_ok()
        || is_legacy_ipv4_address(host)
    {
        return None;
    }

    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return None;
        }
    }

    Some(host.to_ascii_lowercase())
}

fn is_legacy_ipv4_address(host: &str) -> bool {
    let mut parts = [0u64; 4];
    let mut count = 0usize;
    for part in host.split('.') {
        if count == parts.len() {
            return false;
        }
        let Some(value) = parse_ipv4_number(part) else {
            return false;
        };
        parts[count] = value;
        count += 1;
    }

    match count {
        1 => parts[0] <= u32::MAX as u64,
        2 => parts[0] <= 0xff && parts[1] <= 0x00ff_ffff,
        3 => parts[0] <= 0xff && parts[1] <= 0xff && parts[2] <= 0xffff,
        4 => parts[..4].iter().all(|part| *part <= 0xff),
        _ => false,
    }
}

fn parse_ipv4_number(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        if hex.is_empty() {
            return Some(0);
        }
        return u64::from_str_radix(hex, 16).ok();
    }
    if part.len() > 1 && part.starts_with('0') {
        return u64::from_str_radix(part, 8)
            .or_else(|_| part.parse::<u64>())
            .ok();
    }
    part.parse().ok()
}

fn matched(protocol: SniffProtocol, host: String) -> SniffResult {
    SniffResult::Matched(SniffedHost { protocol, host })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn passive_observer_classifies_tls_and_forwards_exact_bytes() {
        let hello = client_hello("observe.example", true);
        let mut sent = hello.clone();
        sent.extend_from_slice(b"application-data");
        let (mut peer, inner) = tokio::io::duplex(sent.len() * 2);
        peer.write_all(&sent).await.unwrap();
        peer.shutdown().await.unwrap();
        let (mut observed, handle) =
            SniffingIo::new(inner, DEFAULT_MAX_SNIFF_BYTES, Duration::from_secs(1));

        let mut forwarded = Vec::new();
        observed.read_to_end(&mut forwarded).await.unwrap();

        assert_eq!(forwarded, sent);
        assert_eq!(
            handle.observation(),
            SniffObservation {
                outcome: SniffOutcome::Matched,
                protocol: Some(SniffProtocol::Tls),
                host: Some("observe.example".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn passive_observer_reports_limit_without_truncating_forwarded_bytes() {
        let sent = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (mut peer, inner) = tokio::io::duplex(128);
        peer.write_all(sent).await.unwrap();
        peer.shutdown().await.unwrap();
        let (mut observed, handle) = SniffingIo::new(inner, 1, Duration::from_secs(1));

        let mut forwarded = Vec::new();
        observed.read_to_end(&mut forwarded).await.unwrap();

        assert_eq!(forwarded, sent);
        assert_eq!(handle.observation().outcome, SniffOutcome::LimitExceeded);
    }

    #[tokio::test]
    async fn passive_observer_timeout_does_not_delay_or_drop_bytes() {
        let sent = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (mut peer, inner) = tokio::io::duplex(128);
        peer.write_all(sent).await.unwrap();
        peer.shutdown().await.unwrap();
        let (mut observed, handle) = SniffingIo::new(inner, 128, Duration::ZERO);

        let mut forwarded = Vec::new();
        observed.read_to_end(&mut forwarded).await.unwrap();

        assert_eq!(forwarded, sent);
        assert_eq!(handle.observation().outcome, SniffOutcome::Timeout);
    }

    #[tokio::test]
    async fn passive_observer_reports_incomplete_on_empty_stream() {
        let (peer, inner) = tokio::io::duplex(16);
        drop(peer);
        let (mut observed, handle) =
            SniffingIo::new(inner, DEFAULT_MAX_SNIFF_BYTES, Duration::from_secs(1));
        let mut forwarded = Vec::new();

        observed.read_to_end(&mut forwarded).await.unwrap();

        assert!(forwarded.is_empty());
        assert_eq!(handle.observation().outcome, SniffOutcome::Incomplete);
    }

    #[tokio::test]
    async fn prefix_capture_returns_match_and_every_consumed_byte() {
        let payload = b"GET /route HTTP/1.1\r\nHost: route.example\r\n\r\nbody";
        let (mut peer, mut stream) = tokio::io::duplex(128);
        peer.write_all(payload).await.unwrap();
        peer.shutdown().await.unwrap();

        let captured = capture_prefix(&mut stream, DEFAULT_MAX_SNIFF_BYTES, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(captured.bytes, payload);
        assert_eq!(
            captured.observation,
            SniffObservation {
                outcome: SniffOutcome::Matched,
                protocol: Some(SniffProtocol::Http),
                host: Some("route.example".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn prefix_capture_times_out_without_waiting_for_stream_eof() {
        let (_peer, mut stream) = tokio::io::duplex(16);

        let captured = capture_prefix(&mut stream, 16, Duration::from_millis(20))
            .await
            .unwrap();

        assert!(captured.bytes.is_empty());
        assert_eq!(captured.observation.outcome, SniffOutcome::Timeout);
    }

    #[tokio::test]
    async fn prefix_capture_enforces_limit_and_preserves_captured_byte() {
        let (mut peer, mut stream) = tokio::io::duplex(16);
        peer.write_all(b"GET").await.unwrap();

        let captured = capture_prefix(&mut stream, 1, Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(captured.bytes, b"G");
        assert_eq!(captured.observation.outcome, SniffOutcome::LimitExceeded);
    }

    #[tokio::test]
    async fn passive_observer_expires_and_clears_partial_data_while_stream_is_idle() {
        let partial = b"GET / HTTP/1.1\r\nCookie: private-value";
        let (mut peer, inner) = tokio::io::duplex(128);
        let (mut observed, handle) =
            SniffingIo::new(inner, DEFAULT_MAX_SNIFF_BYTES, Duration::from_millis(50));
        peer.write_all(partial).await.unwrap();
        let mut forwarded = vec![0u8; partial.len()];
        observed.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, partial);
        {
            let state = handle
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(!state.prefix.is_empty());
            assert!(state.observation.is_none());
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        {
            let state = handle
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(state.prefix.is_empty());
            assert_eq!(
                state.observation.as_ref().map(|value| value.outcome),
                Some(SniffOutcome::Timeout)
            );
        }

        peer.write_all(b"\r\n\r\n").await.unwrap();
        let mut tail = [0u8; 4];
        observed.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"\r\n\r\n");
    }

    #[test]
    fn incremental_observer_handles_byte_at_a_time_http_and_tls() {
        let http = b"GET / HTTP/1.1\r\nHost: bytewise.example\r\n\r\n";
        let mut http_state = ObserveState::new(
            DEFAULT_MAX_SNIFF_BYTES,
            Duration::from_secs(1),
            Arc::new(tokio::sync::Notify::new()),
        );
        for byte in http {
            http_state.observe(std::slice::from_ref(byte));
        }
        assert_eq!(
            http_state.snapshot(),
            SniffObservation {
                outcome: SniffOutcome::Matched,
                protocol: Some(SniffProtocol::Http),
                host: Some("bytewise.example".to_string()),
            }
        );

        let hello = client_hello_with_alpn("bytewise.example", true, vec![vec![b'a'; 250]; 20]);
        let mut tls_state = ObserveState::new(
            HARD_MAX_SNIFF_BYTES,
            Duration::from_secs(1),
            Arc::new(tokio::sync::Notify::new()),
        );
        for byte in &hello {
            tls_state.observe(std::slice::from_ref(byte));
        }
        assert_eq!(
            tls_state.snapshot(),
            SniffObservation {
                outcome: SniffOutcome::Matched,
                protocol: Some(SniffProtocol::Tls),
                host: Some("bytewise.example".to_string()),
            }
        );
    }

    #[test]
    fn classifies_tls_sni_from_fragmentable_client_hello() {
        let hello = client_hello("Example.COM", true);

        assert_eq!(
            classify_prefix(&hello, HARD_MAX_SNIFF_BYTES),
            matched(SniffProtocol::Tls, "example.com")
        );
        for cut in [1, 4, hello.len() - 1] {
            assert_eq!(
                classify_prefix(&hello[..cut], HARD_MAX_SNIFF_BYTES),
                SniffResult::NeedMore
            );
        }
    }

    #[test]
    fn classifies_client_hello_split_across_tls_records() {
        let hello = client_hello("example.com", true);
        let (fragmented, first_record_end) = split_first_tls_record(&hello, 7);

        assert_eq!(
            classify_prefix(&fragmented[..first_record_end], HARD_MAX_SNIFF_BYTES),
            SniffResult::NeedMore
        );
        assert_eq!(
            classify_prefix(&fragmented, HARD_MAX_SNIFF_BYTES),
            matched(SniffProtocol::Tls, "example.com")
        );
    }

    #[test]
    fn classifies_client_hello_larger_than_rustls_read_chunk() {
        let protocols = (0..20)
            .map(|index| {
                let mut protocol = vec![b'a' + (index % 26) as u8; 250];
                protocol.extend_from_slice(index.to_string().as_bytes());
                protocol
            })
            .collect();
        let hello = client_hello_with_alpn("example.com", true, protocols);
        assert!(hello.len() > 4096);

        assert_eq!(
            classify_prefix(&hello, HARD_MAX_SNIFF_BYTES),
            matched(SniffProtocol::Tls, "example.com")
        );
    }

    #[test]
    fn tls_without_sni_is_unsupported() {
        let hello = client_hello("example.com", false);

        assert_eq!(
            classify_prefix(&hello, HARD_MAX_SNIFF_BYTES),
            SniffResult::Unsupported
        );
    }

    #[test]
    fn malformed_tls_is_rejected() {
        let malformed = [0x16, 0x03, 0x03, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff];

        assert_eq!(
            classify_prefix(&malformed, HARD_MAX_SNIFF_BYTES),
            SniffResult::Malformed
        );
    }

    #[test]
    fn classifies_and_normalizes_http_host() {
        let request = b"GET / HTTP/1.1\r\nHost: Example.COM.:8080\r\nUser-Agent: test\r\n\r\nbody";

        assert_eq!(
            classify_prefix(request, HARD_MAX_SNIFF_BYTES),
            matched(SniffProtocol::Http, "example.com")
        );
    }

    #[test]
    fn proxy_request_target_authority_wins_over_host_header() {
        for (request, expected) in [
            (
                &b"CONNECT target.example:443 HTTP/1.1\r\nHost: decoy.example\r\n\r\n"[..],
                "target.example",
            ),
            (
                &b"GET http://target.example/path HTTP/1.1\r\nHost: decoy.example\r\n\r\n"[..],
                "target.example",
            ),
        ] {
            assert_eq!(
                classify_prefix(request, HARD_MAX_SNIFF_BYTES),
                matched(SniffProtocol::Http, expected)
            );
        }

        for request in [
            &b"CONNECT 127.1:443 HTTP/1.1\r\nHost: decoy.example\r\n\r\n"[..],
            &b"GET http://127.1/path HTTP/1.1\r\nHost: decoy.example\r\n\r\n"[..],
        ] {
            assert_eq!(
                classify_prefix(request, HARD_MAX_SNIFF_BYTES),
                SniffResult::Malformed
            );
        }
    }

    #[test]
    fn partial_http_head_needs_more_bytes() {
        assert_eq!(
            classify_prefix(
                b"GET / HTTP/1.1\r\nHost: example.com\r\n",
                HARD_MAX_SNIFF_BYTES
            ),
            SniffResult::NeedMore
        );
    }

    #[test]
    fn classifies_full_http_method_token_grammar_and_leading_empty_line() {
        for request in [
            &b"!FOO / HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
            &b"\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n"[..],
        ] {
            assert_eq!(
                classify_prefix(request, HARD_MAX_SNIFF_BYTES),
                matched(SniffProtocol::Http, "example.com")
            );
        }
    }

    #[test]
    fn duplicate_http_host_is_malformed() {
        let request = b"GET / HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n";

        assert_eq!(
            classify_prefix(request, HARD_MAX_SNIFF_BYTES),
            SniffResult::Malformed
        );
    }

    #[test]
    fn hostless_http_and_unknown_binary_are_unsupported() {
        assert_eq!(
            classify_prefix(b"GET / HTTP/1.0\r\n\r\n", HARD_MAX_SNIFF_BYTES),
            SniffResult::Unsupported
        );
        assert_eq!(
            classify_prefix(b"\x01\x02\x03\x04", HARD_MAX_SNIFF_BYTES),
            SniffResult::Unsupported
        );
    }

    #[test]
    fn invalid_or_ip_hosts_do_not_become_domain_identity() {
        for host in [
            "127.0.0.1",
            "127.1",
            "2130706433",
            "0x7f000001",
            "0x",
            "0177.1",
            "1.2.3.0x",
            "[::1]",
            "bad_host.example",
            "-bad.example",
            "bad-.example",
        ] {
            let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            assert_eq!(
                classify_prefix(request.as_bytes(), HARD_MAX_SNIFF_BYTES),
                SniffResult::Malformed,
                "{host}"
            );
        }

        assert_eq!(
            classify_prefix(
                b"GET / HTTP/1.1\r\nHost: dead.beef\r\n\r\n",
                HARD_MAX_SNIFF_BYTES
            ),
            matched(SniffProtocol::Http, "dead.beef")
        );
    }

    #[test]
    fn incomplete_input_at_limit_reports_limit_exceeded() {
        assert_eq!(classify_prefix(b"G", 1), SniffResult::LimitExceeded);
        assert_eq!(
            classify_prefix(&vec![b'G'; HARD_MAX_SNIFF_BYTES + 1], usize::MAX),
            SniffResult::LimitExceeded
        );
    }

    fn matched(protocol: SniffProtocol, host: &str) -> SniffResult {
        SniffResult::Matched(SniffedHost {
            protocol,
            host: host.to_string(),
        })
    }

    fn client_hello(server_name: &str, enable_sni: bool) -> Vec<u8> {
        client_hello_with_alpn(server_name, enable_sni, Vec::new())
    }

    fn client_hello_with_alpn(
        server_name: &str,
        enable_sni: bool,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        crate::tls::init_crypto();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        config.enable_sni = enable_sni;
        config.alpn_protocols = alpn_protocols;
        let name = ServerName::try_from(server_name.to_string()).unwrap();
        let mut connection = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut bytes = Vec::new();
        while connection.wants_write() {
            if connection.write_tls(&mut bytes).unwrap() == 0 {
                break;
            }
        }
        bytes
    }

    fn split_first_tls_record(record: &[u8], split_at: usize) -> (Vec<u8>, usize) {
        assert!(record.len() >= 5);
        let payload_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert!(record.len() >= 5 + payload_len);
        assert!(split_at > 0 && split_at < payload_len);
        let payload = &record[5..5 + payload_len];

        let mut fragmented = Vec::with_capacity(record.len() + 5);
        append_tls_record(&mut fragmented, record[1], record[2], &payload[..split_at]);
        let first_record_end = fragmented.len();
        append_tls_record(&mut fragmented, record[1], record[2], &payload[split_at..]);
        fragmented.extend_from_slice(&record[5 + payload_len..]);
        (fragmented, first_record_end)
    }

    fn append_tls_record(out: &mut Vec<u8>, major: u8, minor: u8, payload: &[u8]) {
        out.extend_from_slice(&[
            0x16,
            major,
            minor,
            (payload.len() >> 8) as u8,
            payload.len() as u8,
        ]);
        out.extend_from_slice(payload);
    }
}
