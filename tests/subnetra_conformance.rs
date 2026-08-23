//! Subnetra v1 cross-implementation conformance gate.
//!
//! This is the mechanical proof that Rove's embedded data plane is wire-compatible
//! with the reference (Zig) implementation and any other conformant Subnetra
//! endpoint. It replays the vendored known-answer-test (KAT) vectors —
//! `tests/vectors/subnetra-protocol-vectors.json`, taken verbatim from
//! `jamiesun/subnetra` `tests/protocol-vectors.json` — through Rove's crypto, wire,
//! and session code:
//!
//! * **sender suite** (`vectors`) — pins key derivation and the emitted datagram
//!   bytes;
//! * **obfuscation suite** (`obfuscated_vectors`) — pins the masked on-wire bytes
//!   (§3.4);
//! * **receiver suite** (`receiver_cases`) — pins the accept/drop decision, the
//!   recovered plaintext, and the post-step epoch for a sequence of crafted
//!   datagrams.
//!
//! Per PROTOCOL.md §10, "the vectors win": if this test fails, Rove has drifted
//! from the wire contract and MUST NOT ship. To refresh the vectors after an
//! intentional, `wire_version`-bumping change upstream, re-copy the reference
//! `tests/protocol-vectors.json`.

use rove::subnetra::crypto::{self, AeadKey};
use rove::subnetra::session::{RxOutcome, RxSession};
use rove::subnetra::wire::{self, Header};
use serde_json::Value;

const VECTORS_JSON: &str = include_str!("vectors/subnetra-protocol-vectors.json");

fn suite() -> Value {
    serde_json::from_str(VECTORS_JSON).expect("vendored KAT vectors must be valid JSON")
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn arr32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    assert_eq!(v.len(), 32, "expected 32-byte hex, got {}", v.len());
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

/// Parse + validate + accept a *plain* (unobfuscated) datagram, collapsing every
/// rejection path (§5.2, §5) to a single `Drop`, exactly as an endpoint must.
fn receive_plain(session: &mut RxSession, datagram: &[u8]) -> RxOutcome {
    let Some((hdr, body)) = wire::split(datagram) else {
        return RxOutcome::Drop; // shorter than header + tag (§5.2)
    };
    let Some(header) = Header::parse(hdr) else {
        return RxOutcome::Drop;
    };
    if !header.is_valid() {
        return RxOutcome::Drop; // bad version / reserved flag / zero epoch (§5.2)
    }
    session.accept(&header, body)
}

#[test]
fn top_level_parameters_match_v1() {
    let d = suite();
    assert_eq!(d["protocol"], "subnetra");
    assert_eq!(d["wire_version"], 1);
    assert_eq!(d["header_len"], crypto::HEADER_LEN as u64);
    assert_eq!(d["tag_len"], crypto::TAG_LEN as u64);
    assert_eq!(d["max_plaintext"], rove::subnetra::INNER_MTU as u64);
}

#[test]
fn sender_vectors_are_reproduced_byte_for_byte() {
    let d = suite();
    let vectors = d["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());

    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let i = &v["input"];
        let o = &v["output"];

        let psk = arr32(i["psk"].as_str().unwrap());
        let from_id = i["from_id"].as_u64().unwrap() as u16;
        let to_id = i["to_id"].as_u64().unwrap() as u16;
        let epoch = i["epoch"].as_u64().unwrap();
        let seq = i["seq"].as_u64().unwrap();
        let plaintext = unhex(i["plaintext"].as_str().unwrap());

        let lk = crypto::link_key(&psk, from_id, to_id);
        let sk = crypto::session_key(&lk, epoch);
        let aead = AeadKey::new(&sk);
        let datagram = wire::seal_datagram(&lk, &aead, from_id, epoch, seq, 0, &plaintext, false);

        assert_eq!(
            hex(&lk),
            o["link_key"].as_str().unwrap(),
            "{name}: link_key"
        );
        assert_eq!(
            hex(&sk),
            o["session_key"].as_str().unwrap(),
            "{name}: session_key"
        );
        assert_eq!(
            hex(&datagram),
            o["datagram"].as_str().unwrap(),
            "{name}: datagram"
        );
    }
}

#[test]
fn obfuscated_vectors_are_reproduced_byte_for_byte() {
    let d = suite();
    let by_name: std::collections::HashMap<&str, &Value> = d["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["name"].as_str().unwrap(), v))
        .collect();

    let obf = d["obfuscated_vectors"]
        .as_array()
        .expect("obfuscated array");
    assert!(!obf.is_empty());

    for ov in obf {
        let name = ov["name"].as_str().unwrap();
        let base = by_name[name];
        let i = &base["input"];

        let psk = arr32(i["psk"].as_str().unwrap());
        let from_id = i["from_id"].as_u64().unwrap() as u16;
        let to_id = i["to_id"].as_u64().unwrap() as u16;
        let epoch = i["epoch"].as_u64().unwrap();
        let seq = i["seq"].as_u64().unwrap();
        let plaintext = unhex(i["plaintext"].as_str().unwrap());

        let lk = crypto::link_key(&psk, from_id, to_id);
        let aead = AeadKey::new(&crypto::session_key(&lk, epoch));
        let datagram = wire::seal_datagram(&lk, &aead, from_id, epoch, seq, 0, &plaintext, true);

        assert_eq!(
            hex(&datagram),
            ov["datagram"].as_str().unwrap(),
            "{name}: obfuscated datagram"
        );
    }
}

/// The obfuscation trial-de-mask path (§3.4): a receiver recomputes the pad from
/// the cleartext tag and its candidate link key, de-masks, checks self-consistency
/// (`version == 1` && `key_id == peer.id`), then authenticates. Every obfuscated
/// vector must resolve to its correct sender and recover the original plaintext.
#[test]
fn obfuscated_datagrams_are_recovered_by_trial_demask() {
    let d = suite();
    let by_name: std::collections::HashMap<&str, &Value> = d["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["name"].as_str().unwrap(), v))
        .collect();

    for ov in d["obfuscated_vectors"].as_array().unwrap() {
        let name = ov["name"].as_str().unwrap();
        let i = &by_name[name]["input"];
        let psk = arr32(i["psk"].as_str().unwrap());
        let from_id = i["from_id"].as_u64().unwrap() as u16;
        let to_id = i["to_id"].as_u64().unwrap() as u16;
        let expected_pt = i["plaintext"].as_str().unwrap();
        let datagram = unhex(ov["datagram"].as_str().unwrap());

        // Receiver knows the link (peer from_id -> us to_id) and its psk.
        let rx_lk = crypto::link_key(&psk, from_id, to_id);
        let tag = wire::datagram_tag(&datagram).expect("has tag");
        let pad = crypto::obfuscation_pad(&rx_lk, &tag);
        let clear = wire::demask_header(&datagram[..crypto::HEADER_LEN], &pad);
        let header = Header::parse(&clear).unwrap();
        assert!(
            header.is_valid() && header.key_id == from_id,
            "{name}: trial de-mask must recover a self-consistent header"
        );

        let mut session = RxSession::new(rx_lk);
        let body = &datagram[crypto::HEADER_LEN..];
        match session.accept(&header, body) {
            RxOutcome::Accept(pt) => assert_eq!(hex(&pt), expected_pt, "{name}: plaintext"),
            RxOutcome::Drop => panic!("{name}: obfuscated datagram should authenticate"),
        }
    }
}

#[test]
fn receiver_cases_reach_the_same_decisions() {
    let d = suite();
    let cases = d["receiver_cases"]
        .as_array()
        .expect("receiver_cases array");
    assert!(!cases.is_empty());

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let link = &case["link"];
        let psk = arr32(link["psk"].as_str().unwrap());
        let from_id = link["from_id"].as_u64().unwrap() as u16;
        let to_id = link["to_id"].as_u64().unwrap() as u16;
        let init_epoch = case["init_epoch"].as_u64().unwrap();

        let rx_lk = crypto::link_key(&psk, from_id, to_id);
        let mut session = RxSession::with_epoch(rx_lk, init_epoch);

        for (idx, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            let note = step["note"].as_str().unwrap_or("");
            let datagram = unhex(step["datagram"].as_str().unwrap());
            let expect = step["expect"].as_str().unwrap();
            let outcome = receive_plain(&mut session, &datagram);

            match expect {
                "accept" => match outcome {
                    RxOutcome::Accept(pt) => {
                        let expected_pt = step["plaintext"].as_str().unwrap();
                        assert_eq!(
                            hex(&pt),
                            expected_pt,
                            "{name} step {idx} ({note}): plaintext"
                        );
                    }
                    RxOutcome::Drop => {
                        panic!("{name} step {idx} ({note}): expected accept, got drop")
                    }
                },
                "drop" => assert!(
                    matches!(outcome, RxOutcome::Drop),
                    "{name} step {idx} ({note}): expected drop, got accept"
                ),
                other => panic!("{name} step {idx}: unknown expect {other:?}"),
            }

            let epoch_after = step["epoch_after"].as_u64().unwrap();
            assert_eq!(
                session.current_epoch(),
                epoch_after,
                "{name} step {idx} ({note}): epoch_after"
            );
        }
    }
}
