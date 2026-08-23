//! TUIC v5 wire codec (see <https://github.com/tuic-protocol/tuic/blob/master/SPEC.md>).
//!
//! A command is `VER(0x05) | TYPE(1) | OPT`. Streams (uni/bi) are read
//! incrementally; QUIC datagrams arrive as one buffer and are parsed whole.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt};

pub const VERSION: u8 = 0x05;

pub mod cmd {
    pub const AUTHENTICATE: u8 = 0x00;
    pub const CONNECT: u8 = 0x01;
    pub const PACKET: u8 = 0x02;
    pub const DISSOCIATE: u8 = 0x03;
    pub const HEARTBEAT: u8 = 0x04;
}

mod atyp {
    pub const NONE: u8 = 0xff;
    pub const DOMAIN: u8 = 0x00;
    pub const V4: u8 = 0x01;
    pub const V6: u8 = 0x02;
}

/// A TUIC address (`TYPE | ADDR | PORT`). `None` appears on non-first UDP
/// fragments, which this build does not carry (no fragmentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    None,
    Domain(String, u16),
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
}

impl Address {
    /// The `(host, port)` this address targets, or `None` for the `None` type.
    pub fn host_port(&self) -> Option<(String, u16)> {
        match self {
            Address::None => None,
            Address::Domain(h, p) => Some((h.clone(), *p)),
            Address::V4(ip, p) => Some((ip.to_string(), *p)),
            Address::V6(ip, p) => Some((ip.to_string(), *p)),
        }
    }

    /// Build an address from a resolved-or-domain host string and port, choosing
    /// the tightest encoding (v4/v6 literal, else domain).
    pub fn from_host_port(host: &str, port: u16) -> Address {
        if let Ok(v4) = host.parse::<Ipv4Addr>() {
            Address::V4(v4, port)
        } else if let Ok(v6) = host.parse::<Ipv6Addr>() {
            Address::V6(v6, port)
        } else {
            Address::Domain(host.to_string(), port)
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Address::None => out.push(atyp::NONE),
            Address::Domain(h, p) => {
                out.push(atyp::DOMAIN);
                out.push(h.len().min(u8::MAX as usize) as u8);
                out.extend_from_slice(&h.as_bytes()[..h.len().min(u8::MAX as usize)]);
                out.extend_from_slice(&p.to_be_bytes());
            }
            Address::V4(ip, p) => {
                out.push(atyp::V4);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&p.to_be_bytes());
            }
            Address::V6(ip, p) => {
                out.push(atyp::V6);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&p.to_be_bytes());
            }
        }
    }
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Read `VER | TYPE`, returning the command type. Rejects a wrong version.
pub async fn read_command_type<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u8> {
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr).await?;
    if hdr[0] != VERSION {
        return Err(bad("tuic: unsupported protocol version"));
    }
    Ok(hdr[1])
}

/// Read an `Authenticate` command body (`UUID(16) | TOKEN(32)`).
pub async fn read_authenticate<R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<([u8; 16], [u8; 32])> {
    let mut uuid = [0u8; 16];
    let mut token = [0u8; 32];
    r.read_exact(&mut uuid).await?;
    r.read_exact(&mut token).await?;
    Ok((uuid, token))
}

/// Read a TUIC `Address` from a stream.
pub async fn read_address<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Address> {
    let mut t = [0u8; 1];
    r.read_exact(&mut t).await?;
    match t[0] {
        atyp::NONE => Ok(Address::None),
        atyp::DOMAIN => {
            let mut l = [0u8; 1];
            r.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            r.read_exact(&mut d).await?;
            let port = read_u16(r).await?;
            Ok(Address::Domain(
                String::from_utf8_lossy(&d).into_owned(),
                port,
            ))
        }
        atyp::V4 => {
            let mut a = [0u8; 4];
            r.read_exact(&mut a).await?;
            Ok(Address::V4(Ipv4Addr::from(a), read_u16(r).await?))
        }
        atyp::V6 => {
            let mut a = [0u8; 16];
            r.read_exact(&mut a).await?;
            Ok(Address::V6(Ipv6Addr::from(a), read_u16(r).await?))
        }
        _ => Err(bad("tuic: bad address type")),
    }
}

async fn read_u16<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<u16> {
    let mut p = [0u8; 2];
    r.read_exact(&mut p).await?;
    Ok(u16::from_be_bytes(p))
}

/// A parsed `Packet` command header plus the byte offset where its payload
/// begins within the datagram buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    pub assoc_id: u16,
    pub pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub size: u16,
    pub addr: Address,
}

/// A command carried in a single QUIC datagram: either a `Packet` (with its
/// payload) or a `Heartbeat`. Other datagram commands are rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramCommand<'a> {
    Packet(PacketHeader, &'a [u8]),
    Heartbeat,
}

/// Parse a whole datagram (`VER | TYPE | OPT [| payload]`).
pub fn parse_datagram(buf: &[u8]) -> io::Result<DatagramCommand<'_>> {
    if buf.len() < 2 {
        return Err(bad("tuic: datagram too short"));
    }
    if buf[0] != VERSION {
        return Err(bad("tuic: datagram bad version"));
    }
    match buf[1] {
        cmd::HEARTBEAT => Ok(DatagramCommand::Heartbeat),
        cmd::PACKET => {
            let (hdr, off) = parse_packet_header(&buf[2..])?;
            let start = 2 + off;
            let end = start
                .checked_add(hdr.size as usize)
                .ok_or_else(|| bad("tuic: packet size overflow"))?;
            if end > buf.len() {
                return Err(bad("tuic: packet payload truncated"));
            }
            Ok(DatagramCommand::Packet(hdr, &buf[start..end]))
        }
        _ => Err(bad("tuic: unsupported datagram command")),
    }
}

/// Parse a `Packet` header from `buf`, returning it and the number of header
/// bytes consumed (payload starts right after).
pub fn parse_packet_header(buf: &[u8]) -> io::Result<(PacketHeader, usize)> {
    // ASSOC_ID(2) PKT_ID(2) FRAG_TOTAL(1) FRAG_ID(1) SIZE(2) then ADDR.
    if buf.len() < 8 {
        return Err(bad("tuic: packet header too short"));
    }
    let assoc_id = u16::from_be_bytes([buf[0], buf[1]]);
    let pkt_id = u16::from_be_bytes([buf[2], buf[3]]);
    let frag_total = buf[4];
    let frag_id = buf[5];
    let size = u16::from_be_bytes([buf[6], buf[7]]);
    let (addr, addr_len) = parse_address(&buf[8..])?;
    Ok((
        PacketHeader {
            assoc_id,
            pkt_id,
            frag_total,
            frag_id,
            size,
            addr,
        },
        8 + addr_len,
    ))
}

/// Parse a TUIC `Address` from a buffer, returning it and the bytes consumed.
pub fn parse_address(buf: &[u8]) -> io::Result<(Address, usize)> {
    let t = *buf.first().ok_or_else(|| bad("tuic: empty address"))?;
    match t {
        atyp::NONE => Ok((Address::None, 1)),
        atyp::DOMAIN => {
            let l = *buf.get(1).ok_or_else(|| bad("tuic: address domain len"))? as usize;
            let end = 2 + l;
            if buf.len() < end + 2 {
                return Err(bad("tuic: address domain truncated"));
            }
            let host = String::from_utf8_lossy(&buf[2..end]).into_owned();
            let port = u16::from_be_bytes([buf[end], buf[end + 1]]);
            Ok((Address::Domain(host, port), end + 2))
        }
        atyp::V4 => {
            if buf.len() < 7 {
                return Err(bad("tuic: address v4 truncated"));
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((Address::V4(ip, port), 7))
        }
        atyp::V6 => {
            if buf.len() < 19 {
                return Err(bad("tuic: address v6 truncated"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((Address::V6(Ipv6Addr::from(o), port), 19))
        }
        _ => Err(bad("tuic: bad address type")),
    }
}

/// Encode a native-mode `Packet` command datagram (single fragment) carrying
/// `payload` from source `addr` for `assoc_id`.
pub fn encode_packet_datagram(
    assoc_id: u16,
    pkt_id: u16,
    addr: &Address,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + payload.len());
    out.push(VERSION);
    out.push(cmd::PACKET);
    out.extend_from_slice(&assoc_id.to_be_bytes());
    out.extend_from_slice(&pkt_id.to_be_bytes());
    out.push(1); // FRAG_TOTAL
    out.push(0); // FRAG_ID
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    addr.encode(&mut out);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_header_and_authenticate() {
        let mut buf: Vec<u8> = vec![VERSION, cmd::AUTHENTICATE];
        buf.extend_from_slice(&[7u8; 16]);
        buf.extend_from_slice(&[9u8; 32]);
        let mut cur = std::io::Cursor::new(buf);
        assert_eq!(
            read_command_type(&mut cur).await.unwrap(),
            cmd::AUTHENTICATE
        );
        let (uuid, token) = read_authenticate(&mut cur).await.unwrap();
        assert_eq!(uuid, [7u8; 16]);
        assert_eq!(token, [9u8; 32]);
    }

    #[tokio::test]
    async fn rejects_wrong_version() {
        let mut cur = std::io::Cursor::new(vec![0x04, cmd::CONNECT]);
        assert!(read_command_type(&mut cur).await.is_err());
    }

    #[tokio::test]
    async fn reads_all_address_types_from_stream() {
        for addr in [
            Address::Domain("example.com".into(), 443),
            Address::V4(Ipv4Addr::new(1, 2, 3, 4), 80),
            Address::V6(Ipv6Addr::LOCALHOST, 53),
            Address::None,
        ] {
            let mut out = Vec::new();
            addr.encode(&mut out);
            let mut cur = std::io::Cursor::new(out);
            assert_eq!(read_address(&mut cur).await.unwrap(), addr);
        }
    }

    #[test]
    fn packet_datagram_round_trips() {
        let addr = Address::V4(Ipv4Addr::new(9, 9, 9, 9), 5000);
        let dg = encode_packet_datagram(0x1234, 1, &addr, b"hello");
        match parse_datagram(&dg).unwrap() {
            DatagramCommand::Packet(hdr, payload) => {
                assert_eq!(hdr.assoc_id, 0x1234);
                assert_eq!(hdr.frag_total, 1);
                assert_eq!(hdr.size, 5);
                assert_eq!(hdr.addr, addr);
                assert_eq!(payload, b"hello");
            }
            other => panic!("expected packet, got {other:?}"),
        }
    }

    #[test]
    fn heartbeat_datagram_parses() {
        assert_eq!(
            parse_datagram(&[VERSION, cmd::HEARTBEAT]).unwrap(),
            DatagramCommand::Heartbeat
        );
    }

    #[test]
    fn rejects_truncated_packet_payload() {
        let addr = Address::V4(Ipv4Addr::new(1, 1, 1, 1), 1);
        let mut dg = encode_packet_datagram(1, 1, &addr, b"1234567890");
        dg.truncate(dg.len() - 3); // chop payload
        assert!(parse_datagram(&dg).is_err());
    }

    #[test]
    fn from_host_port_picks_tightest_encoding() {
        assert!(matches!(
            Address::from_host_port("1.2.3.4", 1),
            Address::V4(..)
        ));
        assert!(matches!(Address::from_host_port("::1", 1), Address::V6(..)));
        assert!(matches!(
            Address::from_host_port("host.example", 1),
            Address::Domain(..)
        ));
    }
}
