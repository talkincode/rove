//! SOCKS5 UDP ASSOCIATE (RFC 1928) relay.
//!
//! The client authenticates over the TCP control connection (see [`super::socks5`]),
//! sends `UDP ASSOCIATE`, and the server replies with a `BND` address the client
//! then sends UDP datagrams to. Each datagram carries its own target in a SOCKS5
//! UDP header; the server relays it — **through the reverse/2 UDP egress**, the
//! only supported UDP egress — and pumps replies back. The association lives for
//! exactly the TCP control connection's lifetime.
//!
//! Fail-closed: a target whose policy decision is `Block`, or that does not route
//! to a reverse hop (Direct / HTTP / SOCKS5 upstreams cannot carry UDP), is
//! dropped — never sent in the clear. Un-throttled and un-fragmented (FRAG must
//! be 0), matching the TUIC UDP path and the reverse-hop relay.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::debug;

use super::Ctx;
use crate::io::IoStream;
use crate::model::Decision;
use crate::reverse::udp::UdpRelay;
use crate::trace::{TraceCandidate, TraceResult};

const VER: u8 = 0x05;

/// Serve a UDP ASSOCIATE request on an already-authenticated control stream.
pub async fn serve_associate<S: IoStream>(
    mut stream: S,
    ctx: Arc<Ctx>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
    user: String,
    started: Instant,
) -> anyhow::Result<()> {
    // Bind the client-facing relay socket on the same IP the client reached, so
    // the BND address we return is one it can actually send to.
    let bind_ip = local
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let udp = match UdpSocket::bind((bind_ip, 0)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            debug!(error = %e, "socks5 udp: relay bind failed");
            let _ = reply_addr(&mut stream, 0x01, unspecified(bind_ip)).await;
            return Ok(());
        }
    };
    let bnd = udp.local_addr().unwrap_or_else(|_| unspecified(bind_ip));
    reply_addr(&mut stream, 0x00, bnd).await?;

    let bytes_down = Arc::new(AtomicU64::new(0));
    let mut bytes_up: u64 = 0;
    let mut client_addr: Option<SocketAddr> = None;
    let mut relay: Option<Arc<UdpRelay>> = None;
    let mut downlink: Option<tokio::task::JoinHandle<()>> = None;
    let mut decision_name = "direct".to_string();
    let mut egress_info: Option<crate::outbound::EgressInfo> = None;
    let mut failed_attempts: Option<u32> = None;
    let mut result = TraceResult::Ok;
    let mut buf = vec![0u8; 65535];
    let mut ctrl = [0u8; 256];

    loop {
        tokio::select! {
            // The TCP control connection: its close (EOF/error) tears down the
            // association. We don't expect data on it during a relay.
            r = stream.read(&mut ctrl) => {
                match r { Ok(0) | Err(_) => break, Ok(_) => {} }
            }
            // Client -> server UDP datagram.
            r = udp.recv_from(&mut buf) => {
                let (n, src) = match r { Ok(v) => v, Err(_) => break };
                // Latch the client's UDP source on the first datagram; ignore any
                // datagram from a different source (anti-spoofing).
                match client_addr {
                    None => client_addr = Some(src),
                    Some(a) if a != src => continue,
                    _ => {}
                }
                let Some(dg) = parse_udp_datagram(&buf[..n]) else { continue };
                if dg.frag != 0 {
                    continue; // no fragmentation
                }
                let decision = ctx.engine.decide(&user, &dg.host);
                if matches!(decision, Decision::Block) {
                    debug!(user = %user, target = %dg.host, "socks5 udp: blocked by policy");
                    continue;
                }
                if relay.is_none() {
                    decision_name = decision_label(&decision);
                    match crate::outbound::connect_udp(decision, &ctx.egress).await {
                        Ok((r, egress)) => {
                            let r = Arc::new(r);
                            relay = Some(r.clone());
                            egress_info = Some(egress);
                            downlink = Some(spawn_downlink(
                                udp.clone(),
                                r,
                                client_addr.expect("client addr latched"),
                                bytes_down.clone(),
                            ));
                        }
                        Err(e) => {
                            debug!(user = %user, error = %e, "socks5 udp: no egress (fail closed)");
                            failed_attempts = e.chain_attempts().or(failed_attempts);
                            result = TraceResult::Error;
                            continue;
                        }
                    }
                }
                if let Some(r) = &relay {
                    let payload = &buf[dg.data_offset..n];
                    if r.send_to(payload, &dg.host, dg.port).await.is_ok() {
                        bytes_up += payload.len() as u64;
                    }
                }
            }
        }
    }

    if let Some(h) = downlink {
        h.abort();
    }
    let down = bytes_down.load(Ordering::Relaxed);
    report_associate(
        &ctx,
        started,
        peer,
        &user,
        &decision_name,
        egress_info.as_ref(),
        failed_attempts,
        result,
        bytes_up,
        down,
    );
    Ok(())
}

/// The per-association downlink: hop replies -> re-encapsulated SOCKS5 UDP
/// datagram -> client.
fn spawn_downlink(
    udp: Arc<UdpSocket>,
    relay: Arc<UdpRelay>,
    client: SocketAddr,
    bytes_down: Arc<AtomicU64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((data, host, port)) = relay.recv_from().await {
            let pkt = encode_udp_datagram(&host, port, &data);
            if udp.send_to(&pkt, client).await.is_err() {
                break;
            }
            bytes_down.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
    })
}

/// A parsed inbound SOCKS5 UDP datagram header.
struct UdpDatagram {
    frag: u8,
    host: String,
    port: u16,
    data_offset: usize,
}

/// Parse `RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT(2)`, returning the
/// header fields and the offset where DATA begins. `None` on any truncation.
fn parse_udp_datagram(buf: &[u8]) -> Option<UdpDatagram> {
    if buf.len() < 4 {
        return None;
    }
    let frag = buf[2];
    let atyp = buf[3];
    let mut off = 4usize;
    let host = match atyp {
        0x01 => {
            if buf.len() < off + 4 {
                return None;
            }
            let h = Ipv4Addr::new(buf[off], buf[off + 1], buf[off + 2], buf[off + 3]).to_string();
            off += 4;
            h
        }
        0x04 => {
            if buf.len() < off + 16 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            Ipv6Addr::from(o).to_string()
        }
        0x03 => {
            let l = *buf.get(off)? as usize;
            off += 1;
            if l == 0 || buf.len() < off + l {
                return None;
            }
            let h = String::from_utf8_lossy(&buf[off..off + l]).into_owned();
            off += l;
            h
        }
        _ => return None,
    };
    if buf.len() < off + 2 {
        return None;
    }
    let port = u16::from_be_bytes([buf[off], buf[off + 1]]);
    off += 2;
    Some(UdpDatagram {
        frag,
        host,
        port,
        data_offset: off,
    })
}

/// Encode a return SOCKS5 UDP datagram: `RSV(2)=0 | FRAG=0 | ATYP | src | port | DATA`.
fn encode_udp_datagram(host: &str, port: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + data.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2), FRAG=0
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let len = host.len().min(u8::MAX as usize);
            out.push(0x03);
            out.push(len as u8);
            out.extend_from_slice(&host.as_bytes()[..len]);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(data);
    out
}

async fn reply_addr<S: IoStream>(s: &mut S, rep: u8, bnd: SocketAddr) -> std::io::Result<()> {
    let mut out = vec![VER, rep, 0x00];
    match bnd {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    s.write_all(&out).await
}

fn unspecified(ip: IpAddr) -> SocketAddr {
    SocketAddr::new(ip, 0)
}

fn decision_label(decision: &Decision) -> String {
    crate::outbound::decision_label(decision)
}

#[allow(clippy::too_many_arguments)]
fn report_associate(
    ctx: &Arc<Ctx>,
    started: Instant,
    peer: SocketAddr,
    user: &str,
    decision: &str,
    egress: Option<&crate::outbound::EgressInfo>,
    failed_attempts: Option<u32>,
    result: TraceResult,
    bytes_up: u64,
    bytes_down: u64,
) {
    ctx.stats
        .record_listener_bytes(&ctx.listener, bytes_up, bytes_down);
    // Chain decisions count bytes under the physical member outlet.
    let egress_label = egress.map(|e| e.label.as_str()).unwrap_or(decision);
    if egress_label != "block" && egress_label != "direct" {
        ctx.stats
            .record_egress_bytes(egress_label, bytes_up, bytes_down);
    }
    if let Some(log) = &ctx.access_log {
        let is_chain = egress.map(|e| e.chain_id.is_some()).unwrap_or(false);
        let candidate = TraceCandidate {
            listener: ctx.listener.clone(),
            protocol: "socks5-udp".to_string(),
            client_addr: Some(peer.to_string()),
            username: Some(user.to_string()),
            target_host: None, // per-datagram; no single target for an association
            target_port: None,
            traffic: None,
            sniff: None,
            decision: Some(decision.to_string()),
            egress: is_chain.then(|| egress_label.to_string()),
            chain_member: egress.and_then(|e| e.member_id.clone()),
            attempts: egress
                .filter(|e| e.chain_id.is_some())
                .map(|e| e.attempts)
                .or(failed_attempts),
            result,
            failure_stage: None,
            message: Some("udp association".to_string()),
            snapshot_version: ctx.engine.version(),
            duration_ms: started.elapsed().as_millis(),
        };
        log.record(&candidate, bytes_up, bytes_down);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_datagram_round_trips_v4_domain_v6() {
        for host in ["1.2.3.4", "example.com", "2001:db8::1"] {
            let dg = encode_udp_datagram(host, 443, b"payload");
            let parsed = parse_udp_datagram(&dg).expect("parse");
            assert_eq!(parsed.frag, 0);
            assert_eq!(parsed.host, host);
            assert_eq!(parsed.port, 443);
            assert_eq!(&dg[parsed.data_offset..], b"payload");
        }
    }

    #[test]
    fn parse_rejects_truncated_and_reads_frag() {
        // FRAG byte is surfaced so the caller can drop non-zero fragments.
        let mut dg = encode_udp_datagram("1.2.3.4", 53, b"x");
        dg[2] = 5; // set FRAG
        assert_eq!(parse_udp_datagram(&dg).unwrap().frag, 5);
        // truncated header
        assert!(parse_udp_datagram(&[0, 0, 0]).is_none());
        // v4 announced but truncated
        assert!(parse_udp_datagram(&[0, 0, 0, 0x01, 1, 2]).is_none());
        // domain length overruns
        assert!(parse_udp_datagram(&[0, 0, 0, 0x03, 9, b'a']).is_none());
    }

    #[test]
    fn reply_addr_encodes_v4_bnd() {
        // Sanity on the BND reply shape via the encoder path.
        let dg = encode_udp_datagram("127.0.0.1", 9000, b"");
        assert_eq!(dg[3], 0x01); // ATYP v4
        assert_eq!(&dg[4..8], &[127, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([dg[8], dg[9]]), 9000);
    }
}
