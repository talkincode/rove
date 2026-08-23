//! Shared stream abstraction and the bidirectional splice used to pump bytes
//! between an inbound client and an outbound target, with optional per-user
//! byte-rate throttling.

use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

/// Any object-safe, owned duplex stream (TCP or TLS). The blanket impl means
/// every concrete `AsyncRead + AsyncWrite` stream is usable as `Box<dyn IoStream>`.
pub trait IoStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> IoStream for T {}

/// A stream wrapper that replays already-consumed bytes before reading from the
/// underlying stream. Writes always pass straight through to the inner stream.
pub(crate) struct PrefixedIo<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedIo<S> {
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        PrefixedIo {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && buf.remaining() > 0 {
            let available = &self.prefix[self.offset..];
            let take = available.len().min(buf.remaining());
            buf.put_slice(&available[..take]);
            self.offset += take;
            if self.offset == self.prefix.len() {
                self.prefix = Vec::new();
                self.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

/// Bytes moved in each direction by a completed [`splice`] call. `bytes_up` is
/// client -> target, `bytes_down` is target -> client — this is what feeds the
/// access log's per-connection byte counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SpliceStats {
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// Pump bytes both ways until either side closes. `up_rate`/`down_rate` are in
/// bytes/sec; 0 means unlimited.
pub async fn splice<A, B>(a: A, b: B, up_rate: u64, down_rate: u64) -> io::Result<SpliceStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    // up = client -> target ; down = target -> client
    let up = copy_throttled_report(ar, bw, up_rate);
    let down = copy_throttled_report(br, aw, down_rate);
    let (up, down) = tokio::join!(up, down);
    let stats = SpliceStats {
        bytes_up: up.bytes,
        bytes_down: down.bytes,
    };
    match (up.error, down.error) {
        (None, None) => Ok(stats),
        (Some(error), None) if is_benign_splice_close(&error) => Ok(stats),
        (None, Some(error)) if is_benign_splice_close(&error) => Ok(stats),
        (Some(up_error), Some(down_error))
            if is_benign_splice_close(&up_error) && is_benign_splice_close(&down_error) =>
        {
            Ok(stats)
        }
        (Some(error), _) => Err(error),
        (_, Some(error)) => Err(error),
    }
}

pub(crate) async fn copy_throttled<R, W>(mut r: R, mut w: W, rate: u64) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy_throttled_report(&mut r, &mut w, rate)
        .await
        .into_result()
}

struct CopyReport {
    bytes: u64,
    error: Option<io::Error>,
}

impl CopyReport {
    fn ok(bytes: u64) -> Self {
        Self { bytes, error: None }
    }

    fn err(bytes: u64, error: io::Error) -> Self {
        Self {
            bytes,
            error: Some(error),
        }
    }

    fn into_result(self) -> io::Result<u64> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.bytes),
        }
    }
}

async fn copy_throttled_report<R, W>(mut r: R, mut w: W, rate: u64) -> CopyReport
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if rate == 0 {
        return copy_unlimited_report(&mut r, &mut w).await;
    }
    let mut bucket = TokenBucket::new(rate);
    let mut buf = vec![0u8; 32 * 1024];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(n) => n,
            Err(error) => return CopyReport::err(total, error),
        };
        if n == 0 {
            break;
        }
        bucket.consume(n as u64).await;
        if let Err(error) = w.write_all(&buf[..n]).await {
            return CopyReport::err(total, error);
        }
        total += n as u64;
    }
    let _ = w.shutdown().await;
    CopyReport::ok(total)
}

/// Unlimited copy keeps a byte counter even when a write fails mid-stream, so
/// splice stats and benign-reset handling stay accurate. Uses a 64 KiB buffer
/// instead of `tokio::io::copy`'s 8 KiB default: the smaller buffer regresses
/// real TCP splice throughput even though it looks faster on in-memory duplex.
async fn copy_unlimited_report<R, W>(r: &mut R, w: &mut W) -> CopyReport
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(n) => n,
            Err(error) => return CopyReport::err(total, error),
        };
        if n == 0 {
            break;
        }
        if let Err(error) = w.write_all(&buf[..n]).await {
            return CopyReport::err(total, error);
        }
        total += n as u64;
    }
    let _ = w.shutdown().await;
    CopyReport::ok(total)
}

fn is_benign_splice_close(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

pub(crate) struct RateLimiter {
    rate: u64,
    bucket: TokenBucket,
}

impl RateLimiter {
    pub(crate) fn new(rate: u64) -> Self {
        RateLimiter {
            rate,
            bucket: TokenBucket::new(rate),
        }
    }

    pub(crate) async fn write_all<W>(&mut self, writer: &mut W, bytes: &[u8]) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        if self.rate > 0 {
            self.bucket.consume(bytes.len() as u64).await;
        }
        writer.write_all(bytes).await
    }
}

/// Minimal token bucket: capacity == one second of `rate`, refilled continuously.
struct TokenBucket {
    rate: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u64) -> Self {
        TokenBucket {
            rate: rate as f64,
            tokens: rate as f64,
            last: Instant::now(),
        }
    }

    async fn consume(&mut self, n: u64) {
        if self.rate <= 0.0 {
            return;
        }
        let mut need = n as f64;
        loop {
            let now = Instant::now();
            let elapsed = now.duration_since(self.last).as_secs_f64();
            self.last = now;
            self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
            if self.tokens >= need {
                self.tokens -= need;
                return;
            }
            need -= self.tokens;
            self.tokens = 0.0;
            let wait = need / self.rate;
            tokio::time::sleep(Duration::from_secs_f64(wait.min(1.0))).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn prefixed_io_replays_prefix_and_delegates_writes() {
        let (mut peer, inner) = tokio::io::duplex(64);
        peer.write_all(b"inner").await.unwrap();
        let mut stream = PrefixedIo::new(b"prefix-".to_vec(), inner);

        let mut received = [0u8; 12];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"prefix-inner");

        stream.write_all(b"reply").await.unwrap();
        let mut reply = [0u8; 5];
        peer.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    }

    #[tokio::test]
    async fn prefixed_io_handles_prefix_larger_than_read_buffer() {
        let (_peer, inner) = tokio::io::duplex(16);
        let mut stream = PrefixedIo::new(b"abcdef".to_vec(), inner);
        let mut out = Vec::new();

        for _ in 0..3 {
            let mut part = [0u8; 2];
            stream.read_exact(&mut part).await.unwrap();
            out.extend_from_slice(&part);
        }

        assert_eq!(out, b"abcdef");
    }

    #[tokio::test]
    async fn splice_counts_replayed_prefix_as_uploaded_bytes() {
        let (mut client, inbound) = tokio::io::duplex(64);
        let (mut target, outbound) = tokio::io::duplex(64);
        client.write_all(b"tail").await.unwrap();
        client.shutdown().await.unwrap();

        let task = tokio::spawn(splice(
            PrefixedIo::new(b"head".to_vec(), inbound),
            outbound,
            0,
            0,
        ));
        let mut received = [0u8; 8];
        target.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"headtail");
        drop(client);
        drop(target);

        let stats = task.await.unwrap().unwrap();
        assert_eq!(stats.bytes_up, 8);
    }

    #[tokio::test]
    async fn splice_reports_byte_counts_on_unthrottled_fast_path() {
        let (mut client_a, server_a) = tokio::io::duplex(4096);
        let (mut client_b, server_b) = tokio::io::duplex(4096);

        let task = tokio::spawn(splice(server_a, server_b, 0, 0));

        client_a.write_all(b"hello-up").await.unwrap();
        let mut buf = [0u8; 8];
        client_b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-up");

        client_b.write_all(b"hi-down!").await.unwrap();
        let mut buf = [0u8; 8];
        client_a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi-down!");

        drop(client_a);
        drop(client_b);

        let stats = task.await.unwrap().unwrap();
        assert_eq!(stats.bytes_up, 8);
        assert_eq!(stats.bytes_down, 8);
    }

    #[tokio::test]
    async fn splice_reports_byte_counts_on_throttled_path() {
        let (mut client_a, server_a) = tokio::io::duplex(4096);
        let (mut client_b, server_b) = tokio::io::duplex(4096);

        // Large enough rate that the token bucket never blocks the test.
        let task = tokio::spawn(splice(server_a, server_b, 1_000_000, 1_000_000));

        client_a.write_all(b"abc").await.unwrap();
        let mut buf = [0u8; 3];
        client_b.read_exact(&mut buf).await.unwrap();

        client_b.write_all(b"de").await.unwrap();
        let mut buf = [0u8; 2];
        client_a.read_exact(&mut buf).await.unwrap();

        drop(client_a);
        drop(client_b);

        let stats = task.await.unwrap().unwrap();
        assert_eq!(stats.bytes_up, 3);
        assert_eq!(stats.bytes_down, 2);
    }

    #[tokio::test]
    async fn splice_treats_reset_after_peer_completion_as_clean_close() {
        let stats = splice(
            ResetReadSinkWrite,
            OnceReadSinkWrite::new(b"response".to_vec()),
            0,
            0,
        )
        .await
        .unwrap();

        assert_eq!(stats.bytes_up, 0);
        assert_eq!(stats.bytes_down, 8);
    }

    struct ResetReadSinkWrite;

    impl AsyncRead for ResetReadSinkWrite {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::new(
                ErrorKind::ConnectionReset,
                "peer reset",
            )))
        }
    }

    impl AsyncWrite for ResetReadSinkWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct OnceReadSinkWrite {
        data: Vec<u8>,
        offset: usize,
    }

    impl OnceReadSinkWrite {
        fn new(data: Vec<u8>) -> Self {
            Self { data, offset: 0 }
        }
    }

    impl AsyncRead for OnceReadSinkWrite {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset >= self.data.len() {
                return Poll::Ready(Ok(()));
            }
            let remaining = &self.data[self.offset..];
            let take = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..take]);
            self.offset += take;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for OnceReadSinkWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
