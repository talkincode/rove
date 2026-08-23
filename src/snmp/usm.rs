//! SNMPv3 User-based Security Model (RFC 3414) — authentication, privacy
//! and the agent-authoritative engine, for the read-only agent in this
//! crate. GET-class requests only; the response path reuses
//! [`AgentCore::answer`].
//!
//! Scope decisions (issue #61): HMAC-SHA1-96 and HMAC-SHA-256-192
//! (RFC 7860) for auth, AES-128-CFB (RFC 3826) for privacy. MD5 and DES
//! are never implemented. Every failure class maps to its RFC 3414
//! `usmStats` counter, and Reports are only emitted when the request's
//! reportable flag is set — everything else is a silent drop.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use aes::cipher::{BlockEncrypt, KeyInit};
use tracing::warn;

use super::ber::{self, Oid, Reader, Value, Writer};
use super::mib::EngineView;
use super::{concat, constant_time_eq, encode_pdu, parse_pdu, AgentCore, RequestPdu, ResponsePdu};
use crate::config::SnmpV3UserConfig;

pub(super) const USM_SECURITY_MODEL: i64 = 3;
const MAX_MESSAGE_SIZE: i64 = 65507;
/// RFC 3414 §2.2.3: a message is fresh when its engineTime is within ±150
/// seconds of the authoritative engine's clock.
const TIME_WINDOW_SECS: i64 = 150;
/// RFC 3411 limits snmpEngineID to 32 bytes; 5 header bytes leave 27.
const ENGINE_ID_TEXT_MAX: usize = 27;

const FLAG_AUTH: u8 = 0x01;
const FLAG_PRIV: u8 = 0x02;
const FLAG_REPORTABLE: u8 = 0x04;

/// Indices into the `usmStats` counter array; OID is
/// `1.3.6.1.6.3.15.1.1.<index+1>.0`.
const STAT_UNSUPPORTED_SEC_LEVELS: usize = 0;
const STAT_NOT_IN_TIME_WINDOWS: usize = 1;
const STAT_UNKNOWN_USER_NAMES: usize = 2;
const STAT_UNKNOWN_ENGINE_IDS: usize = 3;
const STAT_WRONG_DIGESTS: usize = 4;
const STAT_DECRYPTION_ERRORS: usize = 5;

const USM_STATS_OID: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    Sha1,
    Sha256,
}

impl AuthProtocol {
    fn from_config(name: &str) -> Option<AuthProtocol> {
        match name {
            "sha1" => Some(AuthProtocol::Sha1),
            "sha256" => Some(AuthProtocol::Sha256),
            _ => None,
        }
    }

    /// Truncated MAC length: HMAC-SHA1-96 → 12, HMAC-SHA-256-192 → 24.
    fn mac_len(self) -> usize {
        match self {
            AuthProtocol::Sha1 => 12,
            AuthProtocol::Sha256 => 24,
        }
    }

    fn digest_algorithm(self) -> &'static ring::digest::Algorithm {
        match self {
            AuthProtocol::Sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            AuthProtocol::Sha256 => &ring::digest::SHA256,
        }
    }

    fn hmac_algorithm(self) -> ring::hmac::Algorithm {
        match self {
            AuthProtocol::Sha1 => ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            AuthProtocol::Sha256 => ring::hmac::HMAC_SHA256,
        }
    }
}

/// RFC 3411 SnmpEngineID, "administratively assigned text" format:
/// enterprise number with the high bit set, format octet 4, then the
/// node_id (truncated to fit the 32-byte ceiling). 32473 (0x7ED9) is the
/// RFC 5612 documentation PEN used across this agent.
pub fn derive_engine_id(node_id: &str) -> Vec<u8> {
    let mut id = vec![0x80, 0x00, 0x7E, 0xD9, 0x04];
    let bytes = node_id.as_bytes();
    id.extend_from_slice(&bytes[..bytes.len().min(ENGINE_ID_TEXT_MAX)]);
    id
}

/// RFC 3414 A.2: digest 1MB of the password repeated cyclically.
pub fn password_to_key(alg: AuthProtocol, password: &[u8]) -> Vec<u8> {
    let mut ctx = ring::digest::Context::new(alg.digest_algorithm());
    let mut remaining: usize = 1_048_576;
    while remaining > 0 {
        let take = password.len().min(remaining);
        ctx.update(&password[..take]);
        remaining -= take;
    }
    ctx.finish().as_ref().to_vec()
}

/// RFC 3414 A.2: Kul = H(Ku || snmpEngineID || Ku).
pub fn localize_key(alg: AuthProtocol, ku: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut ctx = ring::digest::Context::new(alg.digest_algorithm());
    ctx.update(ku);
    ctx.update(engine_id);
    ctx.update(ku);
    ctx.finish().as_ref().to_vec()
}

/// AES-128 CFB with a full-block (128-bit) feedback path, the mode RFC 3826
/// prescribes. No padding: the tail block only consumes as much keystream
/// as there is data, so ciphertext length equals plaintext length.
fn cfb128(key: &[u8; 16], iv: &[u8; 16], data: &[u8], decrypt: bool) -> Vec<u8> {
    let cipher = aes::Aes128::new(key.into());
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut keystream = aes::Block::from(feedback);
        cipher.encrypt_block(&mut keystream);
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ keystream[i]);
        }
        if chunk.len() == 16 {
            // Next feedback register is always the ciphertext block.
            if decrypt {
                feedback.copy_from_slice(chunk);
            } else {
                feedback.copy_from_slice(&out[out.len() - 16..]);
            }
        }
    }
    out
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedEngineState {
    engine_id: String,
    engine_boots: u32,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Load the persisted engine state, increment boots for this incarnation,
/// and write it back. Boots restart at 1 whenever the engine ID changes
/// (a renamed node is a new engine as far as RFC 3414 is concerned).
/// Persistence failures degrade to a warning: monitoring must not stop the
/// proxy, though managers may then see a stale-boots time window until
/// re-discovery.
fn load_and_increment_boots(path: &str, engine_id: &[u8]) -> u32 {
    let engine_hex = hex_encode(engine_id);
    let previous: Option<PersistedEngineState> = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok());
    let boots = match previous {
        Some(state) if state.engine_id == engine_hex => {
            state.engine_boots.saturating_add(1).min(i32::MAX as u32)
        }
        _ => 1,
    };
    let state = PersistedEngineState {
        engine_id: engine_hex,
        engine_boots: boots,
    };
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    match serde_json::to_string(&state) {
        Ok(json) => {
            if let Err(e) = std::fs::write(path, json) {
                warn!(error = %e, path, "snmp: cannot persist engine boots");
            }
        }
        Err(e) => warn!(error = %e, "snmp: cannot serialize engine state"),
    }
    boots
}

struct LocalizedUser {
    auth: AuthProtocol,
    auth_key: ring::hmac::Key,
    /// First 16 bytes of the localized privacy key (RFC 3826 §1.2).
    priv_key: Option<[u8; 16]>,
}

/// The authoritative USM engine: localized user keys, engine clock and the
/// six RFC 3414 failure counters.
pub struct UsmAgent {
    engine_id: Vec<u8>,
    boots: u32,
    started: std::time::Instant,
    users: HashMap<Vec<u8>, LocalizedUser>,
    salt: AtomicU64,
    stats: [AtomicU32; 6],
}

/// Owned scoped-PDU contents (RFC 3412 §6.8).
struct ScopedPdu {
    context_engine: Vec<u8>,
    context_name: Vec<u8>,
    pdu: RequestPdu,
}

/// Parsed msgSecurityParameters (RFC 3414 §2.4); slices borrow from the
/// datagram so the MAC field can be located inside the raw bytes.
struct SecurityParams<'a> {
    engine_id: &'a [u8],
    boots: i64,
    time: i64,
    username: &'a [u8],
    auth_params: &'a [u8],
    priv_params: &'a [u8],
}

impl UsmAgent {
    pub fn new(
        users_cfg: &[SnmpV3UserConfig],
        node_id: &str,
        state_path: &str,
    ) -> anyhow::Result<UsmAgent> {
        let engine_id = derive_engine_id(node_id);
        let boots = load_and_increment_boots(state_path, &engine_id);
        let mut users = HashMap::new();
        for user in users_cfg {
            let auth = AuthProtocol::from_config(&user.auth_protocol).ok_or_else(|| {
                anyhow::anyhow!("snmp v3 user {}: unsupported auth protocol", user.username)
            })?;
            let auth_ku = password_to_key(auth, user.auth_password.as_bytes());
            let auth_kul = localize_key(auth, &auth_ku, &engine_id);
            let priv_key = if user.priv_protocol == "aes128" {
                let priv_ku = password_to_key(auth, user.priv_password.as_bytes());
                let priv_kul = localize_key(auth, &priv_ku, &engine_id);
                let mut key = [0u8; 16];
                key.copy_from_slice(&priv_kul[..16]);
                Some(key)
            } else {
                None
            };
            users.insert(
                user.username.clone().into_bytes(),
                LocalizedUser {
                    auth,
                    auth_key: ring::hmac::Key::new(auth.hmac_algorithm(), &auth_kul),
                    priv_key,
                },
            );
        }
        let salt_seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        Ok(UsmAgent {
            engine_id,
            boots,
            started: std::time::Instant::now(),
            users,
            salt: AtomicU64::new(salt_seed),
            stats: Default::default(),
        })
    }

    fn engine_time(&self) -> i64 {
        (self.started.elapsed().as_secs()).min(i32::MAX as u64) as i64
    }

    fn bump(&self, index: usize) -> u32 {
        self.stats[index].fetch_add(1, Ordering::Relaxed) + 1
    }

    pub(super) fn engine_view(&self) -> EngineView {
        EngineView {
            engine_id: self.engine_id.clone(),
            boots: self.boots as i64,
            time: self.engine_time(),
            max_message_size: MAX_MESSAGE_SIZE,
            usm_stats: [
                self.stats[0].load(Ordering::Relaxed),
                self.stats[1].load(Ordering::Relaxed),
                self.stats[2].load(Ordering::Relaxed),
                self.stats[3].load(Ordering::Relaxed),
                self.stats[4].load(Ordering::Relaxed),
                self.stats[5].load(Ordering::Relaxed),
            ],
        }
    }

    /// Handle one SNMPv3 datagram. `msg` is positioned right after
    /// msgVersion; `raw` is the whole datagram (needed for the MAC, which
    /// covers the exact received bytes). `None` = silent drop.
    pub(super) fn handle(
        &self,
        core: &AgentCore,
        raw: &[u8],
        msg: &mut Reader<'_>,
    ) -> Option<Vec<u8>> {
        let parsed = self.parse_envelope(msg);
        let (msg_id, flags, sec, mut data_reader) = match parsed {
            Ok(fields) => fields,
            Err(_) => {
                core.bump(&core.counters.in_asn_parse_errs);
                return None;
            }
        };
        let reportable = flags & FLAG_REPORTABLE != 0;
        let auth_flag = flags & FLAG_AUTH != 0;
        let priv_flag = flags & FLAG_PRIV != 0;
        if priv_flag && !auth_flag {
            // RFC 3412 §7.2: priv-without-auth is an invalid msgFlags value.
            core.bump(&core.counters.in_asn_parse_errs);
            return None;
        }

        // Plaintext scoped PDU parses early so Reports can echo request-id.
        let plain_scoped = if priv_flag {
            None
        } else {
            parse_scoped(&mut data_reader).ok()
        };
        let report_request_id = plain_scoped.as_ref().map_or(0, |s| s.pdu.request_id);

        // RFC 3414 §3.2 check order. Step 4: engine ID discovery.
        if sec.engine_id != self.engine_id.as_slice() {
            let count = self.bump(STAT_UNKNOWN_ENGINE_IDS);
            return reportable.then(|| {
                self.build_report(
                    msg_id,
                    report_request_id,
                    STAT_UNKNOWN_ENGINE_IDS,
                    count,
                    None,
                )
            });
        }
        // Step 5: user lookup.
        let Some(user) = self.users.get(sec.username) else {
            let count = self.bump(STAT_UNKNOWN_USER_NAMES);
            return reportable.then(|| {
                self.build_report(
                    msg_id,
                    report_request_id,
                    STAT_UNKNOWN_USER_NAMES,
                    count,
                    None,
                )
            });
        };
        // Step 6: security level, fail-closed — a user configured with
        // privacy may only be used at authPriv; priv without a key is
        // equally unsupported.
        let priv_required = user.priv_key.is_some();
        if !auth_flag || (priv_required && !priv_flag) || (priv_flag && !priv_required) {
            let count = self.bump(STAT_UNSUPPORTED_SEC_LEVELS);
            return reportable.then(|| {
                self.build_report(
                    msg_id,
                    report_request_id,
                    STAT_UNSUPPORTED_SEC_LEVELS,
                    count,
                    None,
                )
            });
        }
        // Step 7a: authenticate the exact received bytes.
        if !self.verify_mac(user, raw, sec.auth_params) {
            let count = self.bump(STAT_WRONG_DIGESTS);
            return reportable.then(|| {
                self.build_report(msg_id, report_request_id, STAT_WRONG_DIGESTS, count, None)
            });
        }
        // Step 7b: time window — after auth, and the one Report that MUST
        // itself be authenticated (it carries the trusted clock).
        let our_time = self.engine_time();
        if sec.boots != self.boots as i64 || (sec.time - our_time).abs() > TIME_WINDOW_SECS {
            let count = self.bump(STAT_NOT_IN_TIME_WINDOWS);
            return reportable.then(|| {
                self.build_report(
                    msg_id,
                    report_request_id,
                    STAT_NOT_IN_TIME_WINDOWS,
                    count,
                    Some((sec.username, user)),
                )
            });
        }
        // Step 8: privacy.
        let scoped = if priv_flag {
            let decrypted = self.decrypt_scoped(user, &sec, &mut data_reader);
            match decrypted {
                Some(scoped) => scoped,
                None => {
                    let count = self.bump(STAT_DECRYPTION_ERRORS);
                    return reportable.then(|| {
                        self.build_report(
                            msg_id,
                            report_request_id,
                            STAT_DECRYPTION_ERRORS,
                            count,
                            None,
                        )
                    });
                }
            }
        } else {
            plain_scoped?
        };

        let response = core.answer(&scoped.pdu)?;
        Some(self.encode_response(msg_id, priv_flag, sec.username, user, &scoped, &response))
    }

    /// Parse msgGlobalData + msgSecurityParameters, leaving `msg` at
    /// msgData. Returns the msgData reader by value so lifetimes stay tied
    /// to the datagram.
    fn parse_envelope<'a>(
        &self,
        msg: &mut Reader<'a>,
    ) -> Result<(i64, u8, SecurityParams<'a>, Reader<'a>), ber::BerError> {
        let mut global = msg.read_sequence()?;
        let msg_id = global.read_integer()?;
        let _max_size = global.read_integer()?;
        let flags_bytes = global.read_octet_string()?;
        let sec_model = global.read_integer()?;
        if flags_bytes.len() != 1 || sec_model != USM_SECURITY_MODEL {
            return Err(ber::BerError("unsupported v3 header"));
        }
        let sec_raw = msg.read_octet_string()?;
        let mut sec_seq = Reader::new(sec_raw).read_sequence()?;
        let params = SecurityParams {
            engine_id: sec_seq.read_octet_string()?,
            boots: sec_seq.read_integer()?,
            time: sec_seq.read_integer()?,
            username: sec_seq.read_octet_string()?,
            auth_params: sec_seq.read_octet_string()?,
            priv_params: sec_seq.read_octet_string()?,
        };
        Ok((msg_id, flags_bytes[0], params, *msg))
    }

    /// RFC 3414 §6.3.2: zero the MAC field inside a copy of the received
    /// bytes, recompute, compare in constant time.
    fn verify_mac(&self, user: &LocalizedUser, raw: &[u8], auth_params: &[u8]) -> bool {
        let mac_len = user.auth.mac_len();
        if auth_params.len() != mac_len {
            return false;
        }
        // auth_params borrows from raw, so pointer distance is its offset.
        let offset = auth_params.as_ptr() as usize - raw.as_ptr() as usize;
        if offset + mac_len > raw.len() {
            return false;
        }
        let mut copy = raw.to_vec();
        copy[offset..offset + mac_len].fill(0);
        let tag = ring::hmac::sign(&user.auth_key, &copy);
        constant_time_eq(&tag.as_ref()[..mac_len], auth_params)
    }

    /// RFC 3826 §3.1.4 decryption: IV = boots ‖ time (from the message
    /// header) ‖ the 8-byte salt from msgPrivacyParameters.
    fn decrypt_scoped(
        &self,
        user: &LocalizedUser,
        sec: &SecurityParams<'_>,
        data: &mut Reader<'_>,
    ) -> Option<ScopedPdu> {
        let key = user.priv_key.as_ref()?;
        if sec.priv_params.len() != 8 {
            return None;
        }
        let ciphertext = data.read_octet_string().ok()?;
        let iv = build_iv(sec.boots as u32, sec.time as u32, sec.priv_params);
        let plaintext = cfb128(key, &iv, ciphertext, true);
        parse_scoped(&mut Reader::new(&plaintext)).ok()
    }

    fn next_salt(&self) -> [u8; 8] {
        self.salt.fetch_add(1, Ordering::Relaxed).to_be_bytes()
    }

    /// Encode the Response-PDU with the request's security level: encrypt
    /// under a fresh salt when priv, then sign. Responses clear the
    /// reportable flag (RFC 3412 §7.1).
    fn encode_response(
        &self,
        msg_id: i64,
        priv_flag: bool,
        username: &[u8],
        user: &LocalizedUser,
        scoped: &ScopedPdu,
        response: &ResponsePdu,
    ) -> Vec<u8> {
        let pdu = encode_pdu(ber::TAG_RESPONSE, response);
        let scoped_bytes =
            encode_scoped(&scoped.context_engine, &scoped.context_name, pdu).into_bytes();
        let time = self.engine_time();
        let mut flags = FLAG_AUTH;
        let (msg_data, salt): (Vec<u8>, Vec<u8>) = if priv_flag {
            flags |= FLAG_PRIV;
            let salt = self.next_salt();
            let iv = build_iv(self.boots, time as u32, &salt);
            let key = user.priv_key.as_ref().expect("priv negotiated above");
            let ciphertext = cfb128(key, &iv, &scoped_bytes, false);
            let mut w = Writer::new();
            w.write_octet_string(&ciphertext);
            (w.into_bytes(), salt.to_vec())
        } else {
            (scoped_bytes, Vec::new())
        };
        self.encode_v3_message(msg_id, flags, username, Some(user), &salt, &msg_data, time)
    }

    /// Reports answer protocol-level failures (RFC 3414 §3.2). All are
    /// noAuthNoPriv except notInTimeWindows, which must be signed so the
    /// manager can trust the boots/time it carries.
    fn build_report(
        &self,
        msg_id: i64,
        request_id: i64,
        stat_index: usize,
        count: u32,
        auth_as: Option<(&[u8], &LocalizedUser)>,
    ) -> Vec<u8> {
        let mut oid = Oid::new(USM_STATS_OID);
        oid.0.push(stat_index as u32 + 1);
        oid.0.push(0);
        let report = ResponsePdu {
            request_id,
            error_status: 0,
            error_index: 0,
            bindings: vec![(oid, Value::Counter32(count))],
        };
        let pdu = encode_pdu(ber::TAG_REPORT, &report);
        let msg_data = encode_scoped(&self.engine_id, b"", pdu).into_bytes();
        let time = self.engine_time();
        let (flags, username, user) = match auth_as {
            Some((name, user)) => (FLAG_AUTH, name, Some(user)),
            None => (0u8, &b""[..], None),
        };
        self.encode_v3_message(msg_id, flags, username, user, &[], &msg_data, time)
    }

    /// Serialize one SNMPv3 message. When signing, the message is encoded
    /// twice — MAC field zeroed, HMAC computed over those exact bytes, then
    /// re-encoded with the MAC — which is the RFC 3414 §6.3.1 procedure
    /// without offset bookkeeping (the encoder is deterministic).
    #[allow(clippy::too_many_arguments)]
    fn encode_v3_message(
        &self,
        msg_id: i64,
        flags: u8,
        username: &[u8],
        auth: Option<&LocalizedUser>,
        priv_params: &[u8],
        msg_data: &[u8],
        time: i64,
    ) -> Vec<u8> {
        let build = |mac: &[u8]| -> Vec<u8> {
            let mut global = Writer::new();
            global.write_integer(msg_id);
            global.write_integer(MAX_MESSAGE_SIZE);
            global.write_octet_string(&[flags]);
            global.write_integer(USM_SECURITY_MODEL);
            let mut sec = Writer::new();
            sec.write_octet_string(&self.engine_id);
            sec.write_integer(self.boots as i64);
            sec.write_integer(time);
            sec.write_octet_string(username);
            sec.write_octet_string(mac);
            sec.write_octet_string(priv_params);
            let sec_bytes = Writer::wrap(ber::TAG_SEQUENCE, sec).into_bytes();
            let mut body = Writer::new();
            body.write_integer(super::SNMP_VERSION_3);
            body = concat(body, Writer::wrap(ber::TAG_SEQUENCE, global));
            body.write_octet_string(&sec_bytes);
            body = concat(body, Writer::from_bytes(msg_data.to_vec()));
            Writer::wrap(ber::TAG_SEQUENCE, body).into_bytes()
        };
        match auth {
            None => build(&[]),
            Some(user) => {
                let mac_len = user.auth.mac_len();
                let unsigned = build(&vec![0u8; mac_len]);
                let tag = ring::hmac::sign(&user.auth_key, &unsigned);
                build(&tag.as_ref()[..mac_len])
            }
        }
    }
}

fn build_iv(boots: u32, time: u32, salt: &[u8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&boots.to_be_bytes());
    iv[4..8].copy_from_slice(&time.to_be_bytes());
    iv[8..16].copy_from_slice(&salt[..8]);
    iv
}

fn parse_scoped(reader: &mut Reader<'_>) -> Result<ScopedPdu, ber::BerError> {
    let mut seq = reader.read_sequence()?;
    let context_engine = seq.read_octet_string()?.to_vec();
    let context_name = seq.read_octet_string()?.to_vec();
    let pdu = parse_pdu(&mut seq)?;
    Ok(ScopedPdu {
        context_engine,
        context_name,
        pdu,
    })
}

fn encode_scoped(context_engine: &[u8], context_name: &[u8], pdu: Writer) -> Writer {
    let mut scoped = Writer::new();
    scoped.write_octet_string(context_engine);
    scoped.write_octet_string(context_name);
    scoped = concat(scoped, pdu);
    Writer::wrap(ber::TAG_SEQUENCE, scoped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SnmpConfig, SnmpV3UserConfig};
    use crate::snmp::{AgentCore, AgentIdentity};
    use crate::stats::TrafficStats;
    use std::net::SocketAddr;

    fn tmp_state_path(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rove-usm-{tag}-{nanos}.json"))
            .to_str()
            .unwrap()
            .to_string()
    }

    fn user_cfg(username: &str, auth: &str, with_priv: bool) -> SnmpV3UserConfig {
        SnmpV3UserConfig {
            username: username.to_string(),
            auth_protocol: auth.to_string(),
            auth_password: "auth-password-1".to_string(),
            priv_protocol: if with_priv { "aes128" } else { "" }.to_string(),
            priv_password: if with_priv { "priv-password-1" } else { "" }.to_string(),
        }
    }

    fn v3_core(state_path: &str, users: Vec<SnmpV3UserConfig>) -> AgentCore {
        let cfg = SnmpConfig {
            enable: true,
            listen: "127.0.0.1:0".to_string(),
            community: String::new(),
            state_path: state_path.to_string(),
            v3_users: users,
            ..SnmpConfig::default()
        };
        let stats = TrafficStats::new();
        stats.record_listener_bytes("web", 100, 200);
        stats.record_egress_bytes("direct", 100, 200);
        AgentCore::new(
            &cfg,
            AgentIdentity {
                node_id: "edge-1".to_string(),
                role: crate::snmp::mib::NodeRole::Edge,
                version: "2.0.4".to_string(),
            },
            stats,
        )
        .unwrap()
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:34567".parse().unwrap()
    }

    /// Test-side key material mirroring the agent's derivation.
    struct TestKeys {
        auth: AuthProtocol,
        auth_key: ring::hmac::Key,
        priv_key: Option<[u8; 16]>,
    }

    fn test_keys(engine_id: &[u8], auth: AuthProtocol, with_priv: bool) -> TestKeys {
        let auth_kul = localize_key(auth, &password_to_key(auth, b"auth-password-1"), engine_id);
        let priv_key = with_priv.then(|| {
            let kul = localize_key(auth, &password_to_key(auth, b"priv-password-1"), engine_id);
            let mut key = [0u8; 16];
            key.copy_from_slice(&kul[..16]);
            key
        });
        TestKeys {
            auth,
            auth_key: ring::hmac::Key::new(auth.hmac_algorithm(), &auth_kul),
            priv_key,
        }
    }

    fn get_request_pdu(request_id: i64, oid_parts: &[u32]) -> Writer {
        let mut vb = Writer::new();
        vb.write_oid(&Oid::new(oid_parts));
        vb.write_null();
        let list = Writer::wrap(ber::TAG_SEQUENCE, vb);
        let mut pdu = Writer::new();
        pdu.write_integer(request_id);
        pdu.write_integer(0);
        pdu.write_integer(0);
        pdu = concat(pdu, Writer::wrap(ber::TAG_SEQUENCE, list));
        Writer::wrap(ber::TAG_GET_REQUEST, pdu)
    }

    struct RequestSpec<'a> {
        msg_id: i64,
        flags: u8,
        engine_id: &'a [u8],
        boots: i64,
        time: i64,
        username: &'a [u8],
        keys: Option<&'a TestKeys>,
        scoped: Vec<u8>,
    }

    /// Build an SNMPv3 request the way a manager would.
    fn build_request(spec: &RequestSpec<'_>) -> Vec<u8> {
        let encrypt = spec.flags & FLAG_PRIV != 0;
        let (msg_data, salt): (Vec<u8>, Vec<u8>) = if encrypt {
            let keys = spec.keys.expect("priv needs keys");
            let salt = [9u8; 8];
            let iv = build_iv(spec.boots as u32, spec.time as u32, &salt);
            let ct = cfb128(keys.priv_key.as_ref().unwrap(), &iv, &spec.scoped, false);
            let mut w = Writer::new();
            w.write_octet_string(&ct);
            (w.into_bytes(), salt.to_vec())
        } else {
            (spec.scoped.clone(), Vec::new())
        };
        let build = |mac: &[u8]| -> Vec<u8> {
            let mut global = Writer::new();
            global.write_integer(spec.msg_id);
            global.write_integer(MAX_MESSAGE_SIZE);
            global.write_octet_string(&[spec.flags]);
            global.write_integer(USM_SECURITY_MODEL);
            let mut sec = Writer::new();
            sec.write_octet_string(spec.engine_id);
            sec.write_integer(spec.boots);
            sec.write_integer(spec.time);
            sec.write_octet_string(spec.username);
            sec.write_octet_string(mac);
            sec.write_octet_string(&salt);
            let sec_bytes = Writer::wrap(ber::TAG_SEQUENCE, sec).into_bytes();
            let mut body = Writer::new();
            body.write_integer(3);
            body = concat(body, Writer::wrap(ber::TAG_SEQUENCE, global));
            body.write_octet_string(&sec_bytes);
            body = concat(body, Writer::from_bytes(msg_data.clone()));
            Writer::wrap(ber::TAG_SEQUENCE, body).into_bytes()
        };
        if spec.flags & FLAG_AUTH != 0 {
            let keys = spec.keys.expect("auth needs keys");
            let mac_len = keys.auth.mac_len();
            let unsigned = build(&vec![0u8; mac_len]);
            let tag = ring::hmac::sign(&keys.auth_key, &unsigned);
            build(&tag.as_ref()[..mac_len])
        } else {
            build(&[])
        }
    }

    struct ParsedV3 {
        flags: u8,
        engine_id: Vec<u8>,
        boots: i64,
        time: i64,
        username: Vec<u8>,
        priv_params: Vec<u8>,
        msg_data: Vec<u8>,
        raw: Vec<u8>,
        auth_params: Vec<u8>,
    }

    fn parse_v3(bytes: &[u8]) -> ParsedV3 {
        let mut reader = Reader::new(bytes);
        let mut msg = reader.read_sequence().unwrap();
        assert_eq!(msg.read_integer().unwrap(), 3);
        let mut global = msg.read_sequence().unwrap();
        let _msg_id = global.read_integer().unwrap();
        let _max = global.read_integer().unwrap();
        let flags = global.read_octet_string().unwrap()[0];
        assert_eq!(global.read_integer().unwrap(), USM_SECURITY_MODEL);
        let sec_raw = msg.read_octet_string().unwrap();
        let mut sec = Reader::new(sec_raw).read_sequence().unwrap();
        let engine_id = sec.read_octet_string().unwrap().to_vec();
        let boots = sec.read_integer().unwrap();
        let time = sec.read_integer().unwrap();
        let username = sec.read_octet_string().unwrap().to_vec();
        let auth_params = sec.read_octet_string().unwrap().to_vec();
        let priv_params = sec.read_octet_string().unwrap().to_vec();
        let msg_data = if flags & FLAG_PRIV != 0 {
            msg.read_octet_string().unwrap().to_vec()
        } else {
            let (_, content) = msg.read_tlv().unwrap();
            // Re-wrap so parse_scoped sees the full TLV.
            Writer::wrap(ber::TAG_SEQUENCE, Writer::from_bytes(content.to_vec())).into_bytes()
        };
        ParsedV3 {
            flags,
            engine_id,
            boots,
            time,
            username,
            priv_params,
            msg_data,
            raw: bytes.to_vec(),
            auth_params,
        }
    }

    /// Extract (tag, request_id, bindings) from a plaintext scoped PDU.
    fn parse_scoped_response(msg_data: &[u8]) -> (u8, i64, Vec<(Oid, Value)>) {
        let mut reader = Reader::new(msg_data);
        let mut scoped = reader.read_sequence().unwrap();
        let _engine = scoped.read_octet_string().unwrap();
        let _name = scoped.read_octet_string().unwrap();
        let tag = scoped.peek_tag().unwrap();
        let pdu = parse_pdu(&mut scoped).unwrap();
        (tag, pdu.request_id, pdu.bindings)
    }

    fn engine_of(core: &AgentCore) -> (&UsmAgent, Vec<u8>, u32) {
        let usm = core.usm.as_ref().expect("usm configured");
        (usm, usm.engine_id.clone(), usm.boots)
    }

    #[test]
    fn engine_id_uses_pen_prefix_text_format_and_truncates() {
        let id = derive_engine_id("edge-1");
        assert_eq!(&id[..5], &[0x80, 0x00, 0x7E, 0xD9, 0x04]);
        assert_eq!(&id[5..], b"edge-1");

        let long = "x".repeat(64);
        let id = derive_engine_id(&long);
        assert_eq!(id.len(), 32); // RFC 3411 ceiling
    }

    #[test]
    fn key_localization_matches_rfc3414_sha1_vector() {
        // RFC 3414 A.3.2: password "maplesyrup", engine 00..00 02.
        let engine: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let ku = password_to_key(AuthProtocol::Sha1, b"maplesyrup");
        let kul = localize_key(AuthProtocol::Sha1, &ku, &engine);
        assert_eq!(hex_encode(&kul), "6695febc9288e36282235fc7151f128497b38f3f");
    }

    #[test]
    fn key_localization_matches_sha256_vector() {
        // Same inputs under SHA-256 (RFC 7860 uses the RFC 3414 algorithm);
        // expected value cross-checked against independent implementations.
        let engine: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let ku = password_to_key(AuthProtocol::Sha256, b"maplesyrup");
        let kul = localize_key(AuthProtocol::Sha256, &ku, &engine);
        assert_eq!(
            hex_encode(&kul),
            "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"
        );
    }

    #[test]
    fn cfb128_matches_nist_sp800_38a_f313() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51,
        ];
        let expected = [
            0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c,
            0xfb, 0x4a, 0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad,
            0x9f, 0x1c, 0xe5, 0x8b,
        ];
        let ct = cfb128(&key, &iv, &plaintext, false);
        assert_eq!(ct, expected);
        let pt = cfb128(&key, &iv, &expected, true);
        assert_eq!(pt, plaintext);

        // Partial tail block round-trips too (RFC 3826 has no padding).
        let short = b"snmp scoped pdu tail";
        let ct = cfb128(&key, &iv, short, false);
        assert_eq!(cfb128(&key, &iv, &ct, true), short);
    }

    #[test]
    fn engine_boots_increment_across_restarts_and_reset_on_engine_change() {
        let path = tmp_state_path("boots");
        let engine = derive_engine_id("edge-1");
        assert_eq!(load_and_increment_boots(&path, &engine), 1);
        assert_eq!(load_and_increment_boots(&path, &engine), 2);
        assert_eq!(load_and_increment_boots(&path, &engine), 3);

        let other = derive_engine_id("renamed-node");
        assert_eq!(load_and_increment_boots(&path, &other), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn discovery_gets_unknown_engine_ids_report_with_real_engine_id() {
        let path = tmp_state_path("disco");
        let core = v3_core(&path, vec![user_cfg("cacti", "sha1", true)]);
        let (_, engine_id, boots) = engine_of(&core);

        let scoped = encode_scoped(b"", b"", get_request_pdu(77, &[1, 3, 6, 1, 2, 1, 1, 5, 0]));
        let request = build_request(&RequestSpec {
            msg_id: 1001,
            flags: FLAG_REPORTABLE,
            engine_id: b"",
            boots: 0,
            time: 0,
            username: b"",
            keys: None,
            scoped: scoped.into_bytes(),
        });

        let response = core.handle_datagram(&request, peer()).expect("report");
        let parsed = parse_v3(&response);
        assert_eq!(parsed.flags, 0); // noAuthNoPriv, reportable cleared
        assert_eq!(parsed.engine_id, engine_id);
        assert_eq!(parsed.boots, boots as i64);
        let (tag, request_id, bindings) = parse_scoped_response(&parsed.msg_data);
        assert_eq!(tag, ber::TAG_REPORT);
        assert_eq!(request_id, 77);
        assert_eq!(
            bindings[0].0.to_string(),
            "1.3.6.1.6.3.15.1.1.4.0" // usmStatsUnknownEngineIDs
        );
        assert!(matches!(bindings[0].1, Value::Counter32(1)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn unknown_user_gets_report() {
        let path = tmp_state_path("nouser");
        let core = v3_core(&path, vec![user_cfg("cacti", "sha1", false)]);
        let (_, engine_id, boots) = engine_of(&core);

        let scoped = encode_scoped(
            &engine_id,
            b"",
            get_request_pdu(5, &[1, 3, 6, 1, 2, 1, 1, 5, 0]),
        );
        let request = build_request(&RequestSpec {
            msg_id: 2,
            flags: FLAG_REPORTABLE,
            engine_id: &engine_id,
            boots: boots as i64,
            time: 0,
            username: b"nobody",
            keys: None,
            scoped: scoped.into_bytes(),
        });
        let response = core.handle_datagram(&request, peer()).expect("report");
        let parsed = parse_v3(&response);
        let (tag, _, bindings) = parse_scoped_response(&parsed.msg_data);
        assert_eq!(tag, ber::TAG_REPORT);
        assert_eq!(bindings[0].0.to_string(), "1.3.6.1.6.3.15.1.1.3.0");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn priv_user_rejects_auth_no_priv_requests_fail_closed() {
        let path = tmp_state_path("seclevel");
        let core = v3_core(&path, vec![user_cfg("cacti", "sha1", true)]);
        let (usm, engine_id, boots) = engine_of(&core);
        let keys = test_keys(&engine_id, AuthProtocol::Sha1, true);

        let scoped = encode_scoped(
            &engine_id,
            b"",
            get_request_pdu(6, &[1, 3, 6, 1, 2, 1, 1, 5, 0]),
        );
        let request = build_request(&RequestSpec {
            msg_id: 3,
            flags: FLAG_REPORTABLE | FLAG_AUTH, // authNoPriv against authPriv user
            engine_id: &engine_id,
            boots: boots as i64,
            time: usm.engine_time(),
            username: b"cacti",
            keys: Some(&keys),
            scoped: scoped.into_bytes(),
        });
        let response = core.handle_datagram(&request, peer()).expect("report");
        let parsed = parse_v3(&response);
        let (tag, _, bindings) = parse_scoped_response(&parsed.msg_data);
        assert_eq!(tag, ber::TAG_REPORT);
        assert_eq!(bindings[0].0.to_string(), "1.3.6.1.6.3.15.1.1.1.0");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_password_gets_wrong_digests_report_and_counter() {
        let path = tmp_state_path("digest");
        let core = v3_core(&path, vec![user_cfg("cacti", "sha256", false)]);
        let (usm, engine_id, boots) = engine_of(&core);

        // Keys derived from the wrong password.
        let bad_kul = localize_key(
            AuthProtocol::Sha256,
            &password_to_key(AuthProtocol::Sha256, b"wrong-password"),
            &engine_id,
        );
        let bad_keys = TestKeys {
            auth: AuthProtocol::Sha256,
            auth_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &bad_kul),
            priv_key: None,
        };
        let scoped = encode_scoped(
            &engine_id,
            b"",
            get_request_pdu(8, &[1, 3, 6, 1, 2, 1, 1, 5, 0]),
        );
        let request = build_request(&RequestSpec {
            msg_id: 4,
            flags: FLAG_REPORTABLE | FLAG_AUTH,
            engine_id: &engine_id,
            boots: boots as i64,
            time: usm.engine_time(),
            username: b"cacti",
            keys: Some(&bad_keys),
            scoped: scoped.into_bytes(),
        });
        let response = core.handle_datagram(&request, peer()).expect("report");
        let parsed = parse_v3(&response);
        assert_eq!(parsed.flags, 0);
        let (tag, _, bindings) = parse_scoped_response(&parsed.msg_data);
        assert_eq!(tag, ber::TAG_REPORT);
        assert_eq!(bindings[0].0.to_string(), "1.3.6.1.6.3.15.1.1.5.0");
        assert!(matches!(bindings[0].1, Value::Counter32(1)));
        assert_eq!(usm.stats[STAT_WRONG_DIGESTS].load(Ordering::Relaxed), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stale_time_gets_signed_not_in_time_windows_report() {
        let path = tmp_state_path("window");
        let core = v3_core(&path, vec![user_cfg("cacti", "sha1", false)]);
        let (usm, engine_id, boots) = engine_of(&core);
        let keys = test_keys(&engine_id, AuthProtocol::Sha1, false);

        let scoped = encode_scoped(
            &engine_id,
            b"",
            get_request_pdu(9, &[1, 3, 6, 1, 2, 1, 1, 5, 0]),
        );
        let request = build_request(&RequestSpec {
            msg_id: 5,
            flags: FLAG_REPORTABLE | FLAG_AUTH,
            engine_id: &engine_id,
            boots: boots as i64,
            time: usm.engine_time() + TIME_WINDOW_SECS + 60, // outside window
            username: b"cacti",
            keys: Some(&keys),
            scoped: scoped.into_bytes(),
        });
        let response = core.handle_datagram(&request, peer()).expect("report");
        let parsed = parse_v3(&response);
        // The one report that must be authenticated (carries trusted clock).
        assert_eq!(parsed.flags, FLAG_AUTH);
        assert_eq!(parsed.username, b"cacti");
        assert!(!parsed.auth_params.is_empty());
        let (tag, _, bindings) = parse_scoped_response(&parsed.msg_data);
        assert_eq!(tag, ber::TAG_REPORT);
        assert_eq!(bindings[0].0.to_string(), "1.3.6.1.6.3.15.1.1.2.0");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn garbage_ciphertext_gets_decryption_errors_report() {
        let path = tmp_state_path("decrypt");
        let core = v3_core(&path, vec![user_cfg("cacti", "sha1", true)]);
        let (usm, engine_id, boots) = engine_of(&core);
        let keys = test_keys(&engine_id, AuthProtocol::Sha1, true);

        // Well-signed message whose msgData octet string is noise.
        let mut w = Writer::new();
        w.write_octet_string(&[0xde; 40]);
        let noise = w.into_bytes();
        let build = |mac: &[u8]| -> Vec<u8> {
            let mut global = Writer::new();
            global.write_integer(6);
            global.write_integer(MAX_MESSAGE_SIZE);
            global.write_octet_string(&[FLAG_REPORTABLE | FLAG_AUTH | FLAG_PRIV]);
            global.write_integer(USM_SECURITY_MODEL);
            let mut sec = Writer::new();
            sec.write_octet_string(&engine_id);
            sec.write_integer(boots as i64);
            sec.write_integer(usm.engine_time());
            sec.write_octet_string(b"cacti");
            sec.write_octet_string(mac);
            sec.write_octet_string(&[7u8; 8]);
            let sec_bytes = Writer::wrap(ber::TAG_SEQUENCE, sec).into_bytes();
            let mut body = Writer::new();
            body.write_integer(3);
            body = concat(body, Writer::wrap(ber::TAG_SEQUENCE, global));
            body.write_octet_string(&sec_bytes);
            body = concat(body, Writer::from_bytes(noise.clone()));
            Writer::wrap(ber::TAG_SEQUENCE, body).into_bytes()
        };
        let unsigned = build(&[0u8; 12]);
        let tag = ring::hmac::sign(&keys.auth_key, &unsigned);
        let request = build(&tag.as_ref()[..12]);

        let response = core.handle_datagram(&request, peer()).expect("report");
        let parsed = parse_v3(&response);
        let (tag, _, bindings) = parse_scoped_response(&parsed.msg_data);
        assert_eq!(tag, ber::TAG_REPORT);
        assert_eq!(bindings[0].0.to_string(), "1.3.6.1.6.3.15.1.1.6.0");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auth_priv_get_round_trips_encrypted() {
        let path = tmp_state_path("authpriv");
        let core = v3_core(&path, vec![user_cfg("cacti", "sha256", true)]);
        let (usm, engine_id, boots) = engine_of(&core);
        let keys = test_keys(&engine_id, AuthProtocol::Sha256, true);

        let scoped = encode_scoped(
            &engine_id,
            b"",
            get_request_pdu(42, &[1, 3, 6, 1, 2, 1, 1, 5, 0]), // sysName
        );
        let request = build_request(&RequestSpec {
            msg_id: 7,
            flags: FLAG_REPORTABLE | FLAG_AUTH | FLAG_PRIV,
            engine_id: &engine_id,
            boots: boots as i64,
            time: usm.engine_time(),
            username: b"cacti",
            keys: Some(&keys),
            scoped: scoped.into_bytes(),
        });
        let response = core.handle_datagram(&request, peer()).expect("response");
        let parsed = parse_v3(&response);
        assert_eq!(parsed.flags, FLAG_AUTH | FLAG_PRIV); // reportable cleared
        assert_eq!(parsed.username, b"cacti");

        // Verify the response MAC like a manager would.
        let mac_offset = {
            let hay = &parsed.raw;
            hay.windows(parsed.auth_params.len())
                .position(|w| w == parsed.auth_params.as_slice())
                .unwrap()
        };
        let mut zeroed = parsed.raw.clone();
        zeroed[mac_offset..mac_offset + parsed.auth_params.len()].fill(0);
        let tag = ring::hmac::sign(&keys.auth_key, &zeroed);
        assert_eq!(&tag.as_ref()[..24], parsed.auth_params.as_slice());

        // Decrypt and check the answer.
        let iv = build_iv(parsed.boots as u32, parsed.time as u32, &parsed.priv_params);
        let plaintext = cfb128(keys.priv_key.as_ref().unwrap(), &iv, &parsed.msg_data, true);
        let (tag, request_id, bindings) = parse_scoped_response(&plaintext);
        assert_eq!(tag, ber::TAG_RESPONSE);
        assert_eq!(request_id, 42);
        assert_eq!(bindings[0].0.to_string(), "1.3.6.1.2.1.1.5.0");
        assert!(matches!(&bindings[0].1, Value::OctetString(v) if v == b"edge-1"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auth_no_priv_user_walks_like_v2c() {
        let path = tmp_state_path("authnopriv");
        let core = v3_core(&path, vec![user_cfg("cacti", "sha1", false)]);
        let (usm, engine_id, boots) = engine_of(&core);
        let keys = test_keys(&engine_id, AuthProtocol::Sha1, false);

        let scoped = encode_scoped(
            &engine_id,
            b"",
            get_request_pdu(43, &[1, 3, 6, 1, 2, 1, 1, 5, 0]),
        );
        let request = build_request(&RequestSpec {
            msg_id: 8,
            flags: FLAG_REPORTABLE | FLAG_AUTH,
            engine_id: &engine_id,
            boots: boots as i64,
            time: usm.engine_time(),
            username: b"cacti",
            keys: Some(&keys),
            scoped: scoped.into_bytes(),
        });
        let response = core.handle_datagram(&request, peer()).expect("response");
        let parsed = parse_v3(&response);
        assert_eq!(parsed.flags, FLAG_AUTH);
        let (tag, request_id, bindings) = parse_scoped_response(&parsed.msg_data);
        assert_eq!(tag, ber::TAG_RESPONSE);
        assert_eq!(request_id, 43);
        assert!(matches!(&bindings[0].1, Value::OctetString(v) if v == b"edge-1"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn non_reportable_failures_are_silently_dropped() {
        let path = tmp_state_path("silent");
        let core = v3_core(&path, vec![user_cfg("cacti", "sha1", false)]);
        let (usm, _engine_id, boots) = engine_of(&core);

        // Unknown engine ID without the reportable flag: drop, but count.
        let scoped = encode_scoped(b"", b"", get_request_pdu(1, &[1, 3, 6, 1, 2, 1, 1, 5, 0]));
        let request = build_request(&RequestSpec {
            msg_id: 9,
            flags: 0,
            engine_id: b"other-engine",
            boots: boots as i64,
            time: 0,
            username: b"",
            keys: None,
            scoped: scoped.into_bytes(),
        });
        assert!(core.handle_datagram(&request, peer()).is_none());
        assert_eq!(
            usm.stats[STAT_UNKNOWN_ENGINE_IDS].load(Ordering::Relaxed),
            1
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn usm_stats_and_engine_group_appear_in_mib() {
        let path = tmp_state_path("mibusm");
        // Both v2c and v3 configured: walk the usmStats group over v2c.
        let cfg = SnmpConfig {
            enable: true,
            listen: "127.0.0.1:0".to_string(),
            community: "public".to_string(),
            state_path: path.clone(),
            v3_users: vec![user_cfg("cacti", "sha1", false)],
            ..SnmpConfig::default()
        };
        let core = AgentCore::new(
            &cfg,
            AgentIdentity {
                node_id: "edge-1".to_string(),
                role: crate::snmp::mib::NodeRole::Edge,
                version: "2.0.4".to_string(),
            },
            TrafficStats::new(),
        )
        .unwrap();
        let engine_id = core.usm.as_ref().unwrap().engine_id.clone();

        let view = core.build_view();
        let engine_oid = Oid::new(&[1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0]);
        assert!(
            matches!(view.get(&engine_oid), Value::OctetString(v) if v == engine_id),
            "snmpEngineID must be exposed"
        );
        let boots_oid = Oid::new(&[1, 3, 6, 1, 6, 3, 10, 2, 1, 2, 0]);
        assert!(matches!(view.get(&boots_oid), Value::Integer(1)));
        let stats_oid = Oid::new(&[1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0]);
        assert!(matches!(view.get(&stats_oid), Value::Counter32(0)));
        let _ = std::fs::remove_file(&path);
    }
}
