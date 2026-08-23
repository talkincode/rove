//! Small protocol helpers shared by the HTTP inbound and outbound connectors.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Read bytes until the end-of-headers marker `\r\n\r\n` (or `cap`/EOF). Because
/// proxy clients wait for our reply before sending tunnel data, this does not
/// over-read into the tunnel payload.
pub async fn read_http_head<S>(s: &mut S, cap: usize) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let (mut head, remainder) = read_http_head_with_remainder(s, cap).await?;
    // Preserve the historical helper's behaviour for CONNECT-style callers:
    // any bytes received in the same read remain in the returned buffer.
    head.extend_from_slice(&remainder);
    Ok(head)
}

/// Read one HTTP header block while preserving bytes already read beyond the
/// `\r\n\r\n` delimiter (for example, an absolute-form POST body).
pub async fn read_http_head_with_remainder<S>(
    s: &mut S,
    cap: usize,
) -> io::Result<(Vec<u8>, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(start) = find_sub(&buf, b"\r\n\r\n") {
            let end = start + 4;
            if end > cap {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "header too large",
                ));
            }
            let remainder = buf.split_off(end);
            return Ok((buf, remainder));
        }
        if buf.len() > cap {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too large",
            ));
        }
    }
    Ok((buf, Vec::new()))
}

pub fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// True if the first line of an HTTP response carries a 2xx status.
pub fn http_2xx(head: &[u8]) -> bool {
    let line_end = find_sub(head, b"\r\n").unwrap_or(head.len());
    let line = &head[..line_end];
    let s = String::from_utf8_lossy(line);
    let mut parts = s.split_whitespace();
    let _ = parts.next(); // HTTP/1.1
    matches!(parts.next(), Some(code) if code.starts_with('2'))
}

/// Split `host:port`, supporting `[ipv6]:port`. Used for HTTP CONNECT targets.
pub fn split_host_port(t: &str) -> Option<(String, u16)> {
    let t = t.trim();
    if let Some(rest) = t.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        return Some((h.to_string(), p.parse().ok()?));
    }
    let (h, p) = t.rsplit_once(':')?;
    Some((h.to_string(), p.parse().ok()?))
}

/// Host portion of `host:port` (no brackets handling needed for SNI use).
pub fn host_of(addr: &str) -> &str {
    match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    }
}

/// Length-independent byte comparison, so verifying reverse-hop tokens (and any
/// other short secret) does not leak match length via timing.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
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
    use std::io::ErrorKind;

    #[tokio::test]
    async fn read_http_head_rejects_bytes_beyond_cap() {
        let mut input = &b"GET / HTTP/1.1\r\nHost: example.com\r\n"[..];

        let err = read_http_head(&mut input, 8).await.unwrap_err();

        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_http_head_accepts_header_at_cap() {
        let data = b"GET /\r\n\r\n";
        let mut input = &data[..];

        let head = read_http_head(&mut input, data.len()).await.unwrap();

        assert_eq!(head, data);
    }

    #[tokio::test]
    async fn read_http_head_with_remainder_preserves_request_body() {
        let data = b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\nbody";
        let mut input = &data[..];

        let (head, remainder) = read_http_head_with_remainder(&mut input, 8192)
            .await
            .unwrap();

        assert_eq!(head, b"POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n");
        assert_eq!(remainder, b"body");
    }
}
