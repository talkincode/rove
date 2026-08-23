//! Wire framing for the reverse-hop data plane (`rove-reverse/1`).
//!
//! The protocol is deliberately tiny, line-oriented, versioned, and bounded so
//! it is trivial to exercise with in-memory fixtures. Two frame families ride
//! on QUIC bidirectional streams:
//!
//! * **Register** (hop -> edge, once per connection, on the first stream):
//!   ```text
//!   REGISTER rove-reverse/1
//!   hop-id: <hop_id>
//!   token: <token>
//!   edge-id: <edge_id>        (optional)
//!
//!   ```
//!   Edge replies `OK` or `ERR <code>`.
//!
//! * **Tunnel** (edge -> hop, once per proxied user connection, one stream
//!   each):
//!   ```text
//!   CONNECT <host> <port>
//!   tunnel-id: <opaque>       (optional)
//!
//!   ```
//!   Hop replies `OK` (then raw TCP bytes flow both ways on the same stream)
//!   or `ERR <code>` (then closes the stream, leaving the connection intact).
//!
//! Every header block ends with a blank line and is capped at
//! [`MAX_FRAME_BYTES`]. Frames are read one byte at a time on purpose: the
//! reader must stop *exactly* at the blank-line boundary so it never swallows
//! the raw tunnel payload that follows `OK` on the very same stream.

use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// ALPN protocol identifier negotiated on the reverse-hop QUIC connection.
pub const ALPN: &[u8] = b"rove-reverse/1";

/// Human-readable protocol version, echoed in the `REGISTER` line so a future
/// revision can be detected and rejected explicitly.
pub const PROTOCOL_VERSION: &str = "rove-reverse/1";

/// Hard cap on a single header block. Frames are metadata only (ids, host,
/// port), so a few KiB is generous; anything larger is treated as hostile.
pub const MAX_FRAME_BYTES: usize = 4096;

/// Stable, secret-free `ERR <code>` values. These appear in access-log
/// `message` fields and in hop/edge logs, so they must never carry tokens,
/// passwords, or customer data.
pub mod codes {
    /// Register token missing or not accepted.
    pub const UNAUTHORIZED: &str = "unauthorized";
    /// A live session already exists for this `hop_id` and the edge policy is
    /// to reject the newcomer.
    pub const DUPLICATE_HOP_ID: &str = "duplicate_hop_id";
    /// Frame could not be parsed (bad verb, version, host, or port).
    pub const BAD_REQUEST: &str = "bad_request";
    /// Hop could not open a TCP connection to the requested target.
    pub const CONNECT_FAILED: &str = "connect_failed";
    /// Per-edge or global concurrent-tunnel limit reached.
    pub const AT_CAPACITY: &str = "at_capacity";
    /// Unexpected internal error on the responder.
    pub const INTERNAL: &str = "internal";
    /// The hop did not advertise UDP capability (`caps: udp` in REGISTER), so
    /// the edge refuses to route a UDP association to it. Fails closed — never
    /// silently downgraded to a TCP tunnel or direct route.
    pub const UDP_UNSUPPORTED: &str = "udp_unsupported";
    /// The hop is at its UDP-session capacity ceiling.
    pub const UDP_AT_CAPACITY: &str = "udp_at_capacity";
}

/// Errors surfaced while parsing a frame. Kept free of any dynamic secret
/// material — only structural, stable descriptions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("reverse frame: {0}")]
    Malformed(&'static str),
    #[error("reverse frame: unsupported protocol version")]
    UnsupportedVersion,
}

/// A hop's registration request (hop -> edge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    pub hop_id: String,
    pub token: String,
    /// Optional label identifying which configured edge session this is, for
    /// observability only. The edge does not require or trust it for routing.
    pub edge_id: Option<String>,
    /// Optional capability set the hop advertises (e.g. `udp`). Absent in v1
    /// registrations, which parse to an empty set (TCP tunnels only). The edge
    /// uses this to fail closed when routing a capability the hop lacks, rather
    /// than assuming support. Never trusted for auth — purely feature routing.
    pub caps: Vec<String>,
}

impl RegisterRequest {
    /// True when the hop advertised UDP relay support.
    pub fn supports_udp(&self) -> bool {
        self.caps.iter().any(|c| c == "udp")
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("REGISTER {PROTOCOL_VERSION}\n");
        out.push_str(&format!("hop-id: {}\n", self.hop_id));
        out.push_str(&format!("token: {}\n", self.token));
        if let Some(edge_id) = &self.edge_id {
            out.push_str(&format!("edge-id: {edge_id}\n"));
        }
        if !self.caps.is_empty() {
            out.push_str(&format!("caps: {}\n", self.caps.join(",")));
        }
        out.push('\n');
        out.into_bytes()
    }

    pub fn parse(lines: &[String]) -> Result<Self, FrameError> {
        let first = lines
            .first()
            .ok_or(FrameError::Malformed("empty register frame"))?;
        let version = first
            .strip_prefix("REGISTER ")
            .ok_or(FrameError::Malformed("expected REGISTER verb"))?
            .trim();
        if version != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion);
        }
        let headers = parse_headers(&lines[1..]);
        let hop_id = header(&headers, "hop-id")
            .filter(|v| !v.is_empty())
            .ok_or(FrameError::Malformed("missing hop-id"))?;
        let token = header(&headers, "token").ok_or(FrameError::Malformed("missing token"))?;
        let edge_id = header(&headers, "edge-id").filter(|v| !v.is_empty());
        let caps = header(&headers, "caps")
            .map(|v| {
                v.split(',')
                    .map(|c| c.trim().to_ascii_lowercase())
                    .filter(|c| !c.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        Ok(RegisterRequest {
            hop_id,
            token,
            edge_id,
            caps,
        })
    }
}

/// A per-tunnel connect request (edge -> hop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelRequest {
    pub host: String,
    pub port: u16,
    /// Opaque tunnel correlation id, used only for logs/metrics.
    pub tunnel_id: Option<String>,
}

impl TunnelRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("CONNECT {} {}\n", self.host, self.port);
        if let Some(id) = &self.tunnel_id {
            out.push_str(&format!("tunnel-id: {id}\n"));
        }
        out.push('\n');
        out.into_bytes()
    }

    pub fn parse(lines: &[String]) -> Result<Self, FrameError> {
        let first = lines
            .first()
            .ok_or(FrameError::Malformed("empty tunnel frame"))?;
        let rest = first
            .strip_prefix("CONNECT ")
            .ok_or(FrameError::Malformed("expected CONNECT verb"))?;
        let mut parts = rest.split_whitespace();
        let host = parts
            .next()
            .ok_or(FrameError::Malformed("missing target host"))?;
        let port = parts
            .next()
            .ok_or(FrameError::Malformed("missing target port"))?;
        if parts.next().is_some() {
            return Err(FrameError::Malformed("trailing CONNECT tokens"));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| FrameError::Malformed("target port not a u16"))?;
        if host.is_empty() || host.len() > 255 {
            return Err(FrameError::Malformed("target host length out of range"));
        }
        let headers = parse_headers(&lines[1..]);
        let tunnel_id = header(&headers, "tunnel-id").filter(|v| !v.is_empty());
        Ok(TunnelRequest {
            host: host.to_string(),
            port,
            tunnel_id,
        })
    }
}

/// Edge -> hop: open a UDP association multiplexed over this connection's QUIC
/// datagrams. The **edge** assigns `session_id` (unique per hop connection); the
/// hop allocates one egress `UdpSocket` and maps `session_id -> socket`. Unlike
/// `CONNECT`, no target is committed here — each datagram carries its own
/// destination (see [`Datagram`]), matching SOCKS5 UDP semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociateRequest {
    pub session_id: u32,
    /// Opaque correlation id, used only for logs/metrics.
    pub assoc_id: Option<String>,
}

impl AssociateRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("ASSOCIATE {}\n", self.session_id);
        if let Some(id) = &self.assoc_id {
            out.push_str(&format!("assoc-id: {id}\n"));
        }
        out.push('\n');
        out.into_bytes()
    }

    pub fn parse(lines: &[String]) -> Result<Self, FrameError> {
        let first = lines
            .first()
            .ok_or(FrameError::Malformed("empty associate frame"))?;
        let rest = first
            .strip_prefix("ASSOCIATE ")
            .ok_or(FrameError::Malformed("expected ASSOCIATE verb"))?;
        let session_id: u32 = rest
            .trim()
            .parse()
            .map_err(|_| FrameError::Malformed("associate session id not a u32"))?;
        let headers = parse_headers(&lines[1..]);
        let assoc_id = header(&headers, "assoc-id").filter(|v| !v.is_empty());
        Ok(AssociateRequest {
            session_id,
            assoc_id,
        })
    }
}

/// Edge -> hop: tear down a UDP association. The control stream closing has the
/// same effect; an explicit frame just lets both sides log a clean teardown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DissociateRequest {
    pub session_id: u32,
}

impl DissociateRequest {
    pub fn encode(&self) -> Vec<u8> {
        format!("DISSOCIATE {}\n\n", self.session_id).into_bytes()
    }

    pub fn parse(lines: &[String]) -> Result<Self, FrameError> {
        let first = lines
            .first()
            .ok_or(FrameError::Malformed("empty dissociate frame"))?;
        let rest = first
            .strip_prefix("DISSOCIATE ")
            .ok_or(FrameError::Malformed("expected DISSOCIATE verb"))?;
        let session_id: u32 = rest
            .trim()
            .parse()
            .map_err(|_| FrameError::Malformed("dissociate session id not a u32"))?;
        Ok(DissociateRequest { session_id })
    }
}

/// Responder acknowledgement for either frame family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Ok,
    Err(String),
}

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Reply::Ok => b"OK\n\n".to_vec(),
            Reply::Err(code) => format!("ERR {code}\n\n").into_bytes(),
        }
    }

    pub fn parse(lines: &[String]) -> Result<Self, FrameError> {
        let first = lines.first().map(String::as_str).unwrap_or_default().trim();
        if first == "OK" {
            return Ok(Reply::Ok);
        }
        if first == "ERR" {
            return Ok(Reply::Err(String::new()));
        }
        if let Some(code) = first.strip_prefix("ERR ") {
            return Ok(Reply::Err(code.trim().to_string()));
        }
        Err(FrameError::Malformed("expected OK or ERR reply"))
    }
}

/// SOCKS5-compatible address type tags used in the datagram header.
pub const ATYP_V4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_V6: u8 = 0x04;

/// One UDP packet carried in a single QUIC datagram. Wire layout:
/// `session_id: u32 (BE) | atyp: u8 | dst_addr | dst_port: u16 (BE) | payload`.
/// `dst_addr` is 4 bytes (v4), 16 bytes (v6), or `len: u8` + bytes (domain).
/// There is no payload length prefix: a QUIC datagram is already message-framed,
/// so the payload is simply the tail after the header.
pub struct Datagram<'a> {
    pub session_id: u32,
    pub host: String,
    pub port: u16,
    pub payload: &'a [u8],
}

/// Encode a datagram header + payload. Returns `None` if `host` is a domain
/// longer than 255 bytes (cannot fit the 1-byte length prefix).
pub fn encode_datagram(session_id: u32, host: &str, port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + host.len() + payload.len());
    out.extend_from_slice(&session_id.to_be_bytes());
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            if host.len() > u8::MAX as usize {
                return None;
            }
            out.push(ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

/// Parse a datagram header, returning the borrowed payload tail. Bounds-checks
/// every field so a truncated / hostile datagram yields a structured error
/// rather than a panic.
pub fn parse_datagram(buf: &[u8]) -> Result<Datagram<'_>, FrameError> {
    if buf.len() < 5 {
        return Err(FrameError::Malformed("datagram too short for header"));
    }
    let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let atyp = buf[4];
    let mut off = 5usize;
    let host = match atyp {
        ATYP_V4 => {
            if buf.len() < off + 4 {
                return Err(FrameError::Malformed("datagram truncated ipv4"));
            }
            let a = std::net::Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3]);
            off += 4;
            a.to_string()
        }
        ATYP_V6 => {
            if buf.len() < off + 16 {
                return Err(FrameError::Malformed("datagram truncated ipv6"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            std::net::Ipv6Addr::from(o).to_string()
        }
        ATYP_DOMAIN => {
            let len = *buf
                .get(off)
                .ok_or(FrameError::Malformed("datagram missing domain len"))?
                as usize;
            off += 1;
            if len == 0 {
                return Err(FrameError::Malformed("datagram empty domain"));
            }
            if buf.len() < off + len {
                return Err(FrameError::Malformed("datagram truncated domain"));
            }
            let host = String::from_utf8_lossy(&buf[off..off + len]).to_string();
            off += len;
            host
        }
        _ => return Err(FrameError::Malformed("datagram bad atyp")),
    };
    if buf.len() < off + 2 {
        return Err(FrameError::Malformed("datagram truncated port"));
    }
    let port = u16::from_be_bytes([buf[off], buf[off + 1]]);
    off += 2;
    Ok(Datagram {
        session_id,
        host,
        port,
        payload: &buf[off..],
    })
}

/// Read a single `\n\n`-terminated header block, one byte at a time so the
/// caller keeps the raw byte stream that may immediately follow on the same
/// QUIC stream. Returns the block split into trimmed lines (without the
/// trailing blank line).
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<String>> {
    let mut buf: Vec<u8> = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "reverse frame: eof before blank-line terminator",
            ));
        }
        buf.push(byte[0]);
        if buf.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "reverse frame: exceeds max size",
            ));
        }
        if buf.ends_with(b"\n\n") {
            break;
        }
    }
    Ok(split_lines(&buf))
}

/// Write a frame's bytes and flush, without closing the stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes).await?;
    writer.flush().await
}

fn split_lines(buf: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(buf);
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
        .collect();
    // Drop the trailing empty entries produced by the terminating blank line.
    while matches!(lines.last(), Some(l) if l.is_empty()) {
        lines.pop();
    }
    lines
}

fn parse_headers(lines: &[String]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_round_trips_with_optional_edge_id() {
        let req = RegisterRequest {
            hop_id: "hop-s604".to_string(),
            token: "placeholder-token".to_string(),
            edge_id: Some("edge-tokyo-01".to_string()),
            caps: vec![],
        };
        let bytes = req.encode();
        let lines = split_lines(&bytes);
        assert_eq!(RegisterRequest::parse(&lines).unwrap(), req);
    }

    #[test]
    fn register_without_edge_id_parses() {
        let req = RegisterRequest {
            hop_id: "hop-s604".to_string(),
            token: "t".to_string(),
            edge_id: None,
            caps: vec![],
        };
        let lines = split_lines(&req.encode());
        let parsed = RegisterRequest::parse(&lines).unwrap();
        assert_eq!(parsed.edge_id, None);
        assert_eq!(parsed.hop_id, "hop-s604");
    }

    #[test]
    fn register_rejects_wrong_version() {
        let lines = split_lines(b"REGISTER rove-reverse/9\nhop-id: h\ntoken: t\n\n");
        assert_eq!(
            RegisterRequest::parse(&lines),
            Err(FrameError::UnsupportedVersion)
        );
    }

    #[test]
    fn register_requires_hop_id_and_token() {
        let missing_hop = split_lines(b"REGISTER rove-reverse/1\ntoken: t\n\n");
        assert!(RegisterRequest::parse(&missing_hop).is_err());
        let missing_token = split_lines(b"REGISTER rove-reverse/1\nhop-id: h\n\n");
        assert!(RegisterRequest::parse(&missing_token).is_err());
    }

    #[test]
    fn tunnel_round_trips() {
        let req = TunnelRequest {
            host: "example.com".to_string(),
            port: 443,
            tunnel_id: Some("abc123".to_string()),
        };
        let lines = split_lines(&req.encode());
        assert_eq!(TunnelRequest::parse(&lines).unwrap(), req);
    }

    #[test]
    fn tunnel_rejects_bad_port_and_verb() {
        let bad_port = split_lines(b"CONNECT example.com notaport\n\n");
        assert!(TunnelRequest::parse(&bad_port).is_err());
        let bad_verb = split_lines(b"OPEN example.com 443\n\n");
        assert!(TunnelRequest::parse(&bad_verb).is_err());
    }

    #[test]
    fn reply_round_trips() {
        assert_eq!(
            Reply::parse(&split_lines(&Reply::Ok.encode())).unwrap(),
            Reply::Ok
        );
        let err = Reply::Err(codes::CONNECT_FAILED.to_string());
        assert_eq!(Reply::parse(&split_lines(&err.encode())).unwrap(), err);
    }

    #[tokio::test]
    async fn read_frame_stops_at_blank_line_and_leaves_payload() {
        // A tunnel reply `OK` immediately followed by raw tunnel bytes on the
        // same stream: read_frame must consume only through the blank line.
        let mut stream = std::io::Cursor::new(b"OK\n\nRAWPAYLOAD".to_vec());
        let lines = read_frame(&mut stream).await.unwrap();
        assert_eq!(Reply::parse(&lines).unwrap(), Reply::Ok);
        let mut rest = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut rest)
            .await
            .unwrap();
        assert_eq!(&rest, b"RAWPAYLOAD");
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_input() {
        let mut giant = vec![b'a'; MAX_FRAME_BYTES + 10];
        giant.extend_from_slice(b"\n\n");
        let mut stream = std::io::Cursor::new(giant);
        let err = read_frame(&mut stream).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_frame_reports_eof_before_terminator() {
        let mut stream = std::io::Cursor::new(b"REGISTER rove-reverse/1\n".to_vec());
        let err = read_frame(&mut stream).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn register_caps_round_trip_and_backward_compat() {
        // v2 hop advertising udp
        let req = RegisterRequest {
            hop_id: "h".to_string(),
            token: "t".to_string(),
            edge_id: None,
            caps: vec!["udp".to_string()],
        };
        let parsed = RegisterRequest::parse(&split_lines(&req.encode())).unwrap();
        assert_eq!(parsed, req);
        assert!(parsed.supports_udp());
        // v1 hop with no caps header parses to empty set, no udp.
        let v1 = split_lines(b"REGISTER rove-reverse/1\nhop-id: h\ntoken: t\n\n");
        let parsed_v1 = RegisterRequest::parse(&v1).unwrap();
        assert!(parsed_v1.caps.is_empty());
        assert!(!parsed_v1.supports_udp());
    }

    #[test]
    fn associate_round_trips() {
        let req = AssociateRequest {
            session_id: 42,
            assoc_id: Some("a1".to_string()),
        };
        assert_eq!(
            AssociateRequest::parse(&split_lines(&req.encode())).unwrap(),
            req
        );
        let bare = AssociateRequest {
            session_id: 7,
            assoc_id: None,
        };
        assert_eq!(
            AssociateRequest::parse(&split_lines(&bare.encode())).unwrap(),
            bare
        );
    }

    #[test]
    fn associate_rejects_bad_session_id_and_verb() {
        assert!(AssociateRequest::parse(&split_lines(b"ASSOCIATE notanum\n\n")).is_err());
        assert!(AssociateRequest::parse(&split_lines(b"CONNECT 1\n\n")).is_err());
    }

    #[test]
    fn dissociate_round_trips() {
        let req = DissociateRequest { session_id: 99 };
        assert_eq!(
            DissociateRequest::parse(&split_lines(&req.encode())).unwrap(),
            req
        );
    }

    #[test]
    fn datagram_round_trips_all_atyps() {
        for host in ["1.2.3.4", "2001:db8::1", "example.com"] {
            let bytes = encode_datagram(0xDEADBEEF, host, 443, b"hello").unwrap();
            let dg = parse_datagram(&bytes).unwrap();
            assert_eq!(dg.session_id, 0xDEADBEEF);
            assert_eq!(dg.host, host);
            assert_eq!(dg.port, 443);
            assert_eq!(dg.payload, b"hello");
        }
    }

    #[test]
    fn datagram_allows_empty_payload() {
        let bytes = encode_datagram(1, "1.2.3.4", 53, b"").unwrap();
        let dg = parse_datagram(&bytes).unwrap();
        assert_eq!(dg.payload, b"");
        assert_eq!(dg.port, 53);
    }

    #[test]
    fn datagram_rejects_truncated_and_bad_atyp() {
        assert!(parse_datagram(&[0, 0, 0]).is_err()); // too short
        assert!(parse_datagram(&[0, 0, 0, 1, 0x01, 1, 2]).is_err()); // truncated v4
        assert!(parse_datagram(&[0, 0, 0, 1, 0x09, 1, 2, 3, 4, 0, 53]).is_err()); // bad atyp
                                                                                  // domain length overruns the buffer
        assert!(parse_datagram(&[0, 0, 0, 1, 0x03, 10, b'a', b'b']).is_err());
    }

    #[test]
    fn datagram_rejects_oversized_domain() {
        let long_host = "a".repeat(256);
        assert!(encode_datagram(1, &long_host, 443, b"x").is_none());
    }
}
