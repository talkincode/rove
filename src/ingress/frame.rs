//! Bounded wire codec for `rove-ingress/1`.

use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: &str = "rove-ingress/1";
pub const MAX_FRAME_BYTES: usize = 4096;
pub const MAX_NODE_ID_BYTES: usize = 128;
pub const MAX_LISTENER_ID_BYTES: usize = 128;
pub const MAX_TOKEN_BYTES: usize = 1024;

const DATAGRAM_MAGIC: &[u8; 2] = b"RI";
const DATAGRAM_VERSION: u8 = 1;
const DATAGRAM_UPLINK: u8 = 1;
const DATAGRAM_DOWNLINK: u8 = 2;
const DATAGRAM_FIXED: usize = 2 + 1 + 1 + 8 + 16;

pub mod codes {
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const DUPLICATE_NODE_ID: &str = "duplicate_node_id";
    pub const BAD_REQUEST: &str = "bad_request";
    pub const FORBIDDEN: &str = "forbidden";
    pub const PORT_UNAVAILABLE: &str = "port_unavailable";
    pub const AT_CAPACITY: &str = "at_capacity";
    pub const LOCAL_UNAVAILABLE: &str = "local_unavailable";
    pub const INTERNAL: &str = "internal";
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("ingress frame: {0}")]
    Malformed(&'static str),
    #[error("ingress frame: unsupported protocol version")]
    UnsupportedVersion,
    #[error("ingress frame: header exceeds limit")]
    TooLarge,
    #[error("ingress frame: identifier generation failed")]
    Random,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Id128([u8; 16]);

impl Id128 {
    pub fn random() -> Result<Self, FrameError> {
        let mut bytes = [0u8; 16];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| FrameError::Random)?;
        Ok(Id128(bytes))
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Id128(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn parse_hex(value: &str) -> Result<Self, FrameError> {
        let bytes = value.as_bytes();
        if bytes.len() != 32 || !bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(FrameError::Malformed("id must be 32 hex characters"));
        }
        let mut out = [0u8; 16];
        for (output, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
            *output = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        Ok(Id128(out))
    }
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => unreachable!("parse_hex validates every byte"),
    }
}

impl fmt::Display for Id128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        }
    }

    pub fn parse(value: &str) -> Result<Self, FrameError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Transport::Tcp),
            "udp" => Ok(Transport::Udp),
            _ => Err(FrameError::Malformed("transport must be tcp or udp")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    pub node_id: String,
    pub token: String,
}

impl RegisterRequest {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        validate_field(&self.node_id, MAX_NODE_ID_BYTES, "invalid node id")?;
        validate_field(&self.token, MAX_TOKEN_BYTES, "invalid token")?;
        Ok(format!(
            "REGISTER {PROTOCOL_VERSION}\nnode-id: {}\ntoken: {}\n\n",
            self.node_id, self.token
        )
        .into_bytes())
    }

    pub fn parse(lines: &[String]) -> Result<Self, FrameError> {
        let first = lines
            .first()
            .ok_or(FrameError::Malformed("empty register frame"))?;
        let version = first
            .strip_prefix("REGISTER ")
            .ok_or(FrameError::Malformed("expected REGISTER verb"))?;
        if version.trim() != PROTOCOL_VERSION {
            return Err(FrameError::UnsupportedVersion);
        }
        let headers = parse_headers(&lines[1..], &["node-id", "token"])?;
        let node_id = required(&headers, "node-id")?;
        let token = required(&headers, "token")?;
        validate_field(&node_id, MAX_NODE_ID_BYTES, "invalid node id")?;
        validate_field(&token, MAX_TOKEN_BYTES, "invalid token")?;
        Ok(RegisterRequest { node_id, token })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRequest {
    pub listener_id: String,
    pub transport: Transport,
    pub public_port: u16,
}

impl LeaseRequest {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        validate_field(
            &self.listener_id,
            MAX_LISTENER_ID_BYTES,
            "invalid listener id",
        )?;
        Ok(format!(
            "LEASE\nlistener-id: {}\ntransport: {}\npublic-port: {}\n\n",
            self.listener_id,
            self.transport.as_str(),
            self.public_port
        )
        .into_bytes())
    }

    pub fn parse(lines: &[String]) -> Result<Self, FrameError> {
        if lines.first().map(String::as_str) != Some("LEASE") {
            return Err(FrameError::Malformed("expected LEASE verb"));
        }
        let headers = parse_headers(&lines[1..], &["listener-id", "transport", "public-port"])?;
        let listener_id = required(&headers, "listener-id")?;
        validate_field(&listener_id, MAX_LISTENER_ID_BYTES, "invalid listener id")?;
        let transport = Transport::parse(&required(&headers, "transport")?)?;
        let public_port = required(&headers, "public-port")?
            .parse()
            .map_err(|_| FrameError::Malformed("public port is not a u16"))?;
        Ok(LeaseRequest {
            listener_id,
            transport,
            public_port,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenTcpRequest {
    pub lease_id: u64,
    pub ingress_id: Id128,
    pub client_addr: SocketAddr,
    pub public_addr: SocketAddr,
    pub relay_instance_id: String,
    pub tunnel_session_id: Id128,
}

impl OpenTcpRequest {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        validate_field(
            &self.relay_instance_id,
            MAX_NODE_ID_BYTES,
            "invalid relay instance id",
        )?;
        Ok(format!(
            "OPEN_TCP\nlease-id: {}\ningress-id: {}\nclient-addr: {}\npublic-addr: {}\nrelay-id: {}\nsession-id: {}\n\n",
            self.lease_id,
            self.ingress_id,
            self.client_addr,
            self.public_addr,
            self.relay_instance_id,
            self.tunnel_session_id
        )
        .into_bytes())
    }

    pub fn parse(lines: &[String]) -> Result<Self, FrameError> {
        if lines.first().map(String::as_str) != Some("OPEN_TCP") {
            return Err(FrameError::Malformed("expected OPEN_TCP verb"));
        }
        let headers = parse_headers(
            &lines[1..],
            &[
                "lease-id",
                "ingress-id",
                "client-addr",
                "public-addr",
                "relay-id",
                "session-id",
            ],
        )?;
        let relay_instance_id = required(&headers, "relay-id")?;
        validate_field(
            &relay_instance_id,
            MAX_NODE_ID_BYTES,
            "invalid relay instance id",
        )?;
        Ok(OpenTcpRequest {
            lease_id: required(&headers, "lease-id")?
                .parse()
                .map_err(|_| FrameError::Malformed("lease id is not a u64"))?,
            ingress_id: Id128::parse_hex(&required(&headers, "ingress-id")?)?,
            client_addr: required(&headers, "client-addr")?
                .parse()
                .map_err(|_| FrameError::Malformed("invalid client address"))?,
            public_addr: required(&headers, "public-addr")?
                .parse()
                .map_err(|_| FrameError::Malformed("invalid public address"))?,
            relay_instance_id,
            tunnel_session_id: Id128::parse_hex(&required(&headers, "session-id")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Ok(HashMap<String, String>),
    Err(String),
}

impl Reply {
    pub fn ok() -> Self {
        Reply::Ok(HashMap::new())
    }

    pub fn ok_with(headers: impl IntoIterator<Item = (String, String)>) -> Self {
        Reply::Ok(headers.into_iter().collect())
    }

    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        match self {
            Reply::Err(code) => {
                validate_field(code, 64, "invalid error code")?;
                Ok(format!("ERR {code}\n\n").into_bytes())
            }
            Reply::Ok(headers) => {
                let mut out = String::from("OK\n");
                let mut ordered: Vec<_> = headers.iter().collect();
                ordered.sort_by(|a, b| a.0.cmp(b.0));
                for (name, value) in ordered {
                    validate_header_name(name)?;
                    validate_field(value, 1024, "invalid reply header")?;
                    out.push_str(name);
                    out.push_str(": ");
                    out.push_str(value);
                    out.push('\n');
                }
                out.push('\n');
                if out.len() > MAX_FRAME_BYTES {
                    return Err(FrameError::TooLarge);
                }
                Ok(out.into_bytes())
            }
        }
    }

    pub fn parse(lines: &[String]) -> Result<Self, FrameError> {
        let first = lines.first().ok_or(FrameError::Malformed("empty reply"))?;
        if first == "OK" {
            return Ok(Reply::Ok(parse_headers_unrestricted(&lines[1..])?));
        }
        let code = first
            .strip_prefix("ERR ")
            .ok_or(FrameError::Malformed("expected OK or ERR reply"))?;
        validate_field(code, 64, "invalid error code")?;
        if lines.len() != 1 {
            return Err(FrameError::Malformed("ERR reply must not have headers"));
        }
        Ok(Reply::Err(code.to_string()))
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        match self {
            Reply::Ok(headers) => headers.get(name).map(String::as_str),
            Reply::Err(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datagram<'a> {
    Uplink {
        lease_id: u64,
        flow_id: Id128,
        client_addr: SocketAddr,
        payload: &'a [u8],
    },
    Downlink {
        lease_id: u64,
        flow_id: Id128,
        payload: &'a [u8],
    },
}

impl Datagram<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let extra = match self {
            Datagram::Uplink { client_addr, .. } => match client_addr {
                SocketAddr::V4(_) => 1 + 4 + 2,
                SocketAddr::V6(_) => 1 + 16 + 2,
            },
            Datagram::Downlink { .. } => 0,
        };
        let payload = match self {
            Datagram::Uplink { payload, .. } | Datagram::Downlink { payload, .. } => *payload,
        };
        let mut out = Vec::with_capacity(DATAGRAM_FIXED + extra + payload.len());
        out.extend_from_slice(DATAGRAM_MAGIC);
        out.push(DATAGRAM_VERSION);
        out.push(match self {
            Datagram::Uplink { .. } => DATAGRAM_UPLINK,
            Datagram::Downlink { .. } => DATAGRAM_DOWNLINK,
        });
        let (lease_id, flow_id) = match self {
            Datagram::Uplink {
                lease_id, flow_id, ..
            }
            | Datagram::Downlink {
                lease_id, flow_id, ..
            } => (*lease_id, *flow_id),
        };
        out.extend_from_slice(&lease_id.to_be_bytes());
        out.extend_from_slice(flow_id.as_bytes());
        if let Datagram::Uplink { client_addr, .. } = self {
            encode_addr(&mut out, *client_addr);
        }
        out.extend_from_slice(payload);
        out
    }

    pub fn parse(bytes: &'_ [u8]) -> Result<Datagram<'_>, FrameError> {
        if bytes.len() < DATAGRAM_FIXED {
            return Err(FrameError::Malformed("datagram too short"));
        }
        if &bytes[..2] != DATAGRAM_MAGIC || bytes[2] != DATAGRAM_VERSION {
            return Err(FrameError::UnsupportedVersion);
        }
        let kind = bytes[3];
        let lease_id = u64::from_be_bytes(
            bytes[4..12]
                .try_into()
                .map_err(|_| FrameError::Malformed("missing lease id"))?,
        );
        let flow_id = Id128::from_bytes(
            bytes[12..28]
                .try_into()
                .map_err(|_| FrameError::Malformed("missing flow id"))?,
        );
        match kind {
            DATAGRAM_UPLINK => {
                let (client_addr, offset) = decode_addr(bytes, DATAGRAM_FIXED)?;
                Ok(Datagram::Uplink {
                    lease_id,
                    flow_id,
                    client_addr,
                    payload: &bytes[offset..],
                })
            }
            DATAGRAM_DOWNLINK => Ok(Datagram::Downlink {
                lease_id,
                flow_id,
                payload: &bytes[DATAGRAM_FIXED..],
            }),
            _ => Err(FrameError::Malformed("unknown datagram type")),
        }
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<String>> {
    let mut bytes = Vec::with_capacity(256);
    loop {
        let byte = reader.read_u8().await?;
        bytes.push(byte);
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ingress frame exceeds limit",
            ));
        }
        if bytes.ends_with(b"\n\n") || bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ingress frame is not utf-8"))?;
    let normalized = text.replace("\r\n", "\n");
    Ok(normalized
        .trim_end_matches('\n')
        .split('\n')
        .map(str::to_string)
        .collect())
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ingress frame exceeds limit",
        ));
    }
    writer.write_all(bytes).await?;
    writer.flush().await
}

fn parse_headers(
    lines: &[String],
    allowed: &[&str],
) -> Result<HashMap<String, String>, FrameError> {
    let headers = parse_headers_unrestricted(lines)?;
    if headers.keys().any(|name| !allowed.contains(&name.as_str())) {
        return Err(FrameError::Malformed("unknown header"));
    }
    Ok(headers)
}

fn parse_headers_unrestricted(lines: &[String]) -> Result<HashMap<String, String>, FrameError> {
    let mut headers = HashMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or(FrameError::Malformed("header missing colon"))?;
        let name = name.trim().to_ascii_lowercase();
        validate_header_name(&name)?;
        let value = value.trim().to_string();
        if headers.insert(name, value).is_some() {
            return Err(FrameError::Malformed("duplicate header"));
        }
    }
    Ok(headers)
}

fn required(headers: &HashMap<String, String>, name: &'static str) -> Result<String, FrameError> {
    headers
        .get(name)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(FrameError::Malformed("required header missing"))
}

fn validate_field(value: &str, max: usize, error: &'static str) -> Result<(), FrameError> {
    if value.is_empty()
        || value.len() > max
        || value
            .bytes()
            .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
    {
        return Err(FrameError::Malformed(error));
    }
    Ok(())
}

fn validate_header_name(name: &str) -> Result<(), FrameError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(FrameError::Malformed("invalid header name"));
    }
    Ok(())
}

fn encode_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(addr) => {
            out.push(4);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            out.push(6);
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
}

fn decode_addr(bytes: &[u8], offset: usize) -> Result<(SocketAddr, usize), FrameError> {
    let kind = *bytes
        .get(offset)
        .ok_or(FrameError::Malformed("missing address type"))?;
    match kind {
        4 => {
            let end = offset + 1 + 4 + 2;
            if bytes.len() < end {
                return Err(FrameError::Malformed("truncated ipv4 address"));
            }
            let ip = Ipv4Addr::new(
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
            );
            let port = u16::from_be_bytes([bytes[offset + 5], bytes[offset + 6]]);
            Ok((SocketAddr::new(IpAddr::V4(ip), port), end))
        }
        6 => {
            let end = offset + 1 + 16 + 2;
            if bytes.len() < end {
                return Err(FrameError::Malformed("truncated ipv6 address"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[offset + 1..offset + 17]);
            let port = u16::from_be_bytes([bytes[offset + 17], bytes[offset + 18]]);
            Ok((
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port),
                end,
            ))
        }
        _ => Err(FrameError::Malformed("invalid address type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn register_round_trip_and_rejects_injection() {
        let request = RegisterRequest {
            node_id: "edge-nat-01".into(),
            token: "deployment-secret".into(),
        };
        let bytes = request.encode().unwrap();
        let lines = split(&bytes);
        assert_eq!(RegisterRequest::parse(&lines).unwrap(), request);

        let injected = RegisterRequest {
            node_id: "edge\nlease: attacker".into(),
            token: "secret".into(),
        };
        assert!(injected.encode().is_err());
        assert!(Id128::parse_hex(&format!("{}ab", "€".repeat(10))).is_err());
    }

    #[test]
    fn lease_and_open_tcp_round_trip() {
        let lease = LeaseRequest {
            listener_id: "tuic-in".into(),
            transport: Transport::Udp,
            public_port: 8443,
        };
        assert_eq!(
            LeaseRequest::parse(&split(&lease.encode().unwrap())).unwrap(),
            lease
        );

        let open = OpenTcpRequest {
            lease_id: 9,
            ingress_id: Id128::from_bytes([1; 16]),
            client_addr: "203.0.113.4:50000".parse().unwrap(),
            public_addr: "[2001:db8::1]:443".parse().unwrap(),
            relay_instance_id: "relay-hz-1".into(),
            tunnel_session_id: Id128::from_bytes([2; 16]),
        };
        assert_eq!(
            OpenTcpRequest::parse(&split(&open.encode().unwrap())).unwrap(),
            open
        );
    }

    #[test]
    fn duplicate_and_unknown_headers_fail_closed() {
        let duplicate = vec![
            format!("REGISTER {PROTOCOL_VERSION}"),
            "node-id: a".into(),
            "node-id: b".into(),
            "token: t".into(),
        ];
        assert!(RegisterRequest::parse(&duplicate).is_err());

        let unknown = vec![
            "LEASE".into(),
            "listener-id: a".into(),
            "transport: tcp".into(),
            "public-port: 443".into(),
            "target: 127.0.0.1:22".into(),
        ];
        assert!(LeaseRequest::parse(&unknown).is_err());
    }

    #[test]
    fn datagrams_round_trip_ipv4_ipv6_and_downlink() {
        for client_addr in [
            "203.0.113.8:50000".parse().unwrap(),
            "[2001:db8::8]:50001".parse().unwrap(),
        ] {
            let frame = Datagram::Uplink {
                lease_id: 11,
                flow_id: Id128::from_bytes([3; 16]),
                client_addr,
                payload: b"hello",
            }
            .encode();
            assert_eq!(
                Datagram::parse(&frame).unwrap(),
                Datagram::Uplink {
                    lease_id: 11,
                    flow_id: Id128::from_bytes([3; 16]),
                    client_addr,
                    payload: b"hello",
                }
            );
        }

        let frame = Datagram::Downlink {
            lease_id: 12,
            flow_id: Id128::from_bytes([4; 16]),
            payload: b"world",
        }
        .encode();
        assert_eq!(
            Datagram::parse(&frame).unwrap(),
            Datagram::Downlink {
                lease_id: 12,
                flow_id: Id128::from_bytes([4; 16]),
                payload: b"world",
            }
        );
    }

    #[tokio::test]
    async fn reader_stops_before_raw_payload_and_enforces_limit() {
        let (mut writer, mut reader) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            writer.write_all(b"OK\nlease-id: 7\n\nraw").await.unwrap();
        });
        assert_eq!(
            read_frame(&mut reader).await.unwrap(),
            vec!["OK", "lease-id: 7"]
        );
        let mut raw = [0u8; 3];
        reader.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"raw");

        let oversized = vec![b'a'; MAX_FRAME_BYTES + 1];
        let (mut writer, mut reader) = tokio::io::duplex(oversized.len() + 2);
        tokio::spawn(async move {
            writer.write_all(&oversized).await.unwrap();
        });
        assert_eq!(
            read_frame(&mut reader).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    fn split(bytes: &[u8]) -> Vec<String> {
        std::str::from_utf8(bytes)
            .unwrap()
            .trim_end_matches('\n')
            .split('\n')
            .map(str::to_string)
            .collect()
    }
}
