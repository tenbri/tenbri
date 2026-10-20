//! `@tenbri/wasm`, the offline verifier: checks a stream export, or a set of entries, against a
//! pinned key, in the browser or in Node, with the same `tenbri-core` and `tenbri-merkle` code as
//! the CLI. No I/O and no keys: what it is given and what it pins are all it trusts.

use serde_json::{Value, json};
use tenbri_core::{Broken, Chain, encoding, sign};
use tenbri_merkle::{Hash, Note};
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const REPORT: &str = r#"
/** What a verification found. */
export interface Report {
  /** Verified: at least one entry, nothing broken, against a pinned key. */
  ok: boolean;
  /** The stream id, `tnb1:…`, from the genesis entry. */
  stream: string | null;
  /** Entries checked before the first break, or all of them. */
  entries: number;
  /** The fingerprint the genesis key was checked against; null when unpinned, which only shows
   * the entries agree with their own genesis key. */
  pinnedKey: string | null;
  /** The first broken sequence number and the format's error code (`bad_signature`, …). */
  broken: { seq: number; code: string; message: string } | null;
  /** The size of the checkpoint given, when the entries match it. */
  checkpoint: number | null;
}
"#;

/// The package's version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Verifies a stream export: JSON Lines, one stored entry per line from seq 1, as a stream's
/// batch files concatenated in order. `key` pins the genesis key (`sha256:…` fingerprint or
/// `ed25519:…`); `checkpoint`, a signed checkpoint (C2SP note) seen before, also catches
/// truncation and rewrites behind it. Throws on a malformed key or checkpoint.
#[wasm_bindgen(js_name = verifyExport, unchecked_return_type = "Report")]
pub fn verify_export(
    jsonl: &str,
    key: Option<String>,
    checkpoint: Option<String>,
) -> Result<JsValue, JsError> {
    let jsonl = jsonl.strip_suffix('\n').unwrap_or(jsonl);
    let lines = jsonl.split('\n').filter(|_| !jsonl.is_empty());
    js(verify(lines, key.as_deref(), checkpoint.as_deref()))
}

/// Verifies `entries`, stored lines in sequence order from seq 1; see [`verify_export`].
#[wasm_bindgen(js_name = verifyEntries, unchecked_return_type = "Report")]
pub fn verify_entries(
    entries: Vec<String>,
    key: Option<String>,
    checkpoint: Option<String>,
) -> Result<JsValue, JsError> {
    let lines = entries.iter().map(String::as_str);
    js(verify(lines, key.as_deref(), checkpoint.as_deref()))
}

fn js(r: Result<Value, String>) -> Result<JsValue, JsError> {
    let r = r.map_err(|e| JsError::new(&e))?;
    js_sys::JSON::parse(&r.to_string()).map_err(|_| JsError::new("report"))
}

/// The report of [`verify_export`], as JSON.
fn verify<'a>(
    lines: impl Iterator<Item = &'a str>,
    key: Option<&str>,
    checkpoint: Option<&str>,
) -> Result<Value, String> {
    let pin = key.map(pin).transpose()?;
    let note = checkpoint
        .map(|c| Note::parse(c.as_bytes()))
        .transpose()
        .map_err(|e| format!("checkpoint: {e}"))?;
    let mut chain = Chain::new(pin.as_deref());
    let mut hashes: Vec<Hash> = vec![];
    let mut broken: Option<Broken> = None;
    for line in lines {
        if let Err(b) = chain.push(line.as_bytes()) {
            broken = Some(b);
            break;
        }
        let last = chain
            .last_hash()
            .and_then(|h| encoding::prefixed::<32>(h, "sha256:"));
        hashes.push(last.expect("a chain with entries has a last hash"));
    }
    broken = broken.or_else(|| chain.invalidated().cloned());
    let mut matched = None;
    if let (None, Some(note)) = (&broken, &note) {
        match note.check(&chain, &hashes) {
            Ok(_) => matched = Some(note.checkpoint.size),
            Err(b) => broken = Some(b),
        }
    }
    let entries = broken.as_ref().map_or(chain.seq(), |b| b.seq - 1);
    Ok(json!({
        "ok": broken.is_none() && pin.is_some() && entries > 0,
        "stream": chain.stream(),
        "entries": entries,
        "pinnedKey": pin,
        "broken": broken.map(|b| json!({
            "seq": b.seq,
            "code": b.error.code.as_str(),
            "message": b.error.detail,
        })),
        "checkpoint": matched,
    }))
}

/// A key as a fingerprint: `sha256:…` as given, or the fingerprint of `ed25519:…`.
fn pin(s: &str) -> Result<String, String> {
    if encoding::prefixed::<32>(s, "sha256:").is_some() {
        return Ok(s.to_owned());
    }
    sign::decode_key(s)
        .map(|k| sign::fingerprint(&k))
        .map_err(|_| format!("key {s}: expected sha256:<64 hex> or ed25519:<64 hex>"))
}

/// The conformance vectors, natively under `cargo test` and in Node under `wasm-pack test --node`.
#[cfg(test)]
mod tests {
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use serde_json::Value;

    fn cases(file: &str, key: &str) -> Vec<Value> {
        let v: Value = serde_json::from_str(file).unwrap();
        v[key].as_array().unwrap().clone()
    }

    fn check(c: &Value, checkpoint: Option<&str>) {
        let lines = c["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap());
        let r = super::verify(lines, c["pin"].as_str(), checkpoint).unwrap();
        let (want, name) = (&c["result"], &c["name"]);
        if want["ok"] == true {
            assert_eq!(r["broken"], Value::Null, "{name}");
            assert_eq!(r["entries"], want["entries"], "{name}");
            let pinned = want.get("pinned").is_none_or(|p| p == true);
            assert_eq!(r["ok"], pinned, "{name}");
        } else {
            assert_eq!(r["ok"], false, "{name}");
            assert_eq!(r["broken"]["seq"], want["seq"], "{name}");
            assert_eq!(r["broken"]["code"], want["error"], "{name}");
        }
    }

    #[test]
    fn chains() {
        let v = cases(include_str!("../../../spec/vectors/chains.json"), "cases");
        let run: Vec<_> = v.iter().filter(|c| c.get("skip").is_none()).collect();
        assert!(run.len() >= 30);
        run.into_iter().for_each(|c| check(c, None));
    }

    #[test]
    fn checkpoints() {
        let v = cases(
            include_str!("../../../spec/vectors/checkpoints.json"),
            "streams",
        );
        for c in &v {
            check(c, c["checkpoint"].as_str());
        }
    }

    #[test]
    fn export_and_malformed_input() {
        let v = cases(include_str!("../../../spec/vectors/chains.json"), "cases");
        let lines: Vec<&str> = v[0]["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect();
        let export = lines.join("\n") + "\n";
        let r = super::verify(export.trim_end().split('\n'), v[0]["pin"].as_str(), None).unwrap();
        assert_eq!(
            (r["ok"].clone(), r["entries"].clone()),
            (true.into(), 14.into())
        );
        assert!(super::verify([].into_iter(), v[0]["pin"].as_str(), None).unwrap()["ok"] == false);
        assert!(super::verify([].into_iter(), Some("sha256:00"), None).is_err());
        assert!(super::verify([].into_iter(), None, Some("not a note")).is_err());
    }
}
