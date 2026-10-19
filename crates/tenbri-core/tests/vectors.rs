//! Runs spec/vectors/ through tenbri-core: what every implementation of format v1 must agree on.

use std::path::PathBuf;

use serde_json::Value as J;
use tenbri_core::sign::{ENTRY_PREFIX, HEAD_PREFIX, decode_key, entry_hash, message, verify};
use tenbri_core::{Chain, Head, canon, encoding, parse_line};

fn load(name: &str) -> J {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap()
}

fn s(j: &J) -> &str {
    j.as_str().unwrap()
}

fn cases<'a>(j: &'a J, key: &str) -> &'a Vec<J> {
    j[key].as_array().unwrap()
}

#[test]
fn canonical() {
    let v = load("canonical.json");
    for c in cases(&v, "cases") {
        let input = match c.get("input_hex") {
            Some(h) => (0..s(h).len() / 2)
                .map(|i| u8::from_str_radix(&s(h)[2 * i..2 * i + 2], 16).unwrap())
                .collect(),
            None => s(&c["input"]).as_bytes().to_vec(),
        };
        let got = canon::canonicalize(&input);
        let name = s(&c["name"]);
        match c.get("error") {
            Some(e) => assert_eq!(got.unwrap_err().code.as_str(), s(e), "{name}"),
            None => {
                let want = s(&c["canonical"]);
                assert_eq!(String::from_utf8(got.unwrap()).unwrap(), want, "{name}");
                // The byte-for-byte rule: only the canonical form is a valid stored line.
                assert_eq!(
                    canon::parse_stored(&input).is_ok(),
                    input == want.as_bytes(),
                    "{name}"
                );
                assert!(canon::parse_stored(want.as_bytes()).is_ok(), "{name}");
            }
        }
    }
}

#[test]
fn entries() {
    let v = load("entries.json");
    for c in cases(&v, "valid") {
        let (name, line) = (s(&c["name"]), s(&c["line"]).as_bytes());
        let (entry, value) = parse_line(line).unwrap_or_else(|e| panic!("{name}: {e}"));
        let msg = message(ENTRY_PREFIX, &value, &["sig"]);
        if let Some(input) = c.get("signing_input") {
            assert_eq!(msg, s(input).as_bytes(), "{name}");
        }
        assert_eq!(entry_hash(line), s(&c["hash"]), "{name}");
        let key = decode_key(s(&c["signer_pub"])).unwrap();
        verify(&key, &msg, &entry.sig).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
    for c in cases(&v, "invalid") {
        let (name, line) = (s(&c["name"]), s(&c["line"]).as_bytes());
        let err = match (parse_line(line), c.get("signer_pub")) {
            (Err(e), _) => e,
            (Ok((entry, value)), Some(pk)) => {
                let key = decode_key(s(pk)).unwrap();
                verify(&key, &message(ENTRY_PREFIX, &value, &["sig"]), &entry.sig).expect_err(name)
            }
            (Ok(_), None) => panic!("{name}: accepted"),
        };
        assert_eq!(err.code.as_str(), s(&c["error"]), "{name}: {err}");
    }
}

#[test]
fn heads() {
    let v = load("heads.json");
    for c in cases(&v, "cases") {
        let (name, bytes) = (s(&c["name"]), s(&c["head"]).as_bytes());
        let key = decode_key(s(&c["signer_pub"])).unwrap();
        let got = Head::parse(bytes).and_then(|(head, value)| {
            let msg = message(HEAD_PREFIX, &value, &["sig"]);
            if let Some(input) = c.get("signing_input") {
                assert_eq!(msg, s(input).as_bytes(), "{name}");
            }
            verify(&key, &msg, &head.sig)
        });
        match c.get("error") {
            Some(e) => assert_eq!(got.unwrap_err().code.as_str(), s(e), "{name}"),
            None => got.unwrap_or_else(|e| panic!("{name}: {e}")),
        }
    }
}

/// Feeds a case's lines to a chain; returns (entries, first broken seq and code).
pub fn run_chain(c: &J) -> (u64, Option<(u64, String)>, bool) {
    let mut chain = Chain::new(c["pin"].as_str());
    for line in c["lines"].as_array().unwrap() {
        if let Err(b) = chain.push(s(line).as_bytes()) {
            return (
                chain.seq(),
                Some((b.seq, b.error.code.as_str().into())),
                chain.pinned(),
            );
        }
    }
    let broken = chain
        .invalidated()
        .map(|b| (b.seq, b.error.code.as_str().into()));
    (chain.seq(), broken, chain.pinned())
}

#[test]
fn chains() {
    let v = load("chains.json");
    let mut ran = 0;
    for c in cases(&v, "cases") {
        let name = s(&c["name"]);
        if c.get("skip").is_some() {
            continue;
        }
        let (n, broken, pinned) = run_chain(c);
        let r = &c["result"];
        if r["ok"].as_bool().unwrap() {
            assert_eq!(broken, None, "{name}");
            assert_eq!(n, r["entries"].as_u64().unwrap(), "{name}");
            assert_eq!(
                pinned,
                r.get("pinned").is_none_or(|p| p.as_bool().unwrap()),
                "{name}"
            );
        } else {
            assert_eq!(
                broken,
                Some((r["seq"].as_u64().unwrap(), s(&r["error"]).into())),
                "{name}"
            );
        }
        ran += 1;
    }
    assert!(ran >= 30, "only {ran} chain vectors ran");
}

#[test]
fn keys() {
    let v = load("keys.json");
    for k in cases(&v, "keys") {
        let seed = encoding::unhex::<32>(s(&k["seed"])).unwrap();
        let sk = tenbri_core::sign::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key();
        assert_eq!(tenbri_core::sign::encode_key(&pk), s(&k["pub"]));
        assert_eq!(tenbri_core::sign::fingerprint(&pk), s(&k["fingerprint"]));
        assert_eq!(
            tenbri_core::sign::stream_id(&pk),
            s(&k["stream_id_if_genesis"])
        );
    }
}
