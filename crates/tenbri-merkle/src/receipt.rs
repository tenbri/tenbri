//! Receipts: a self-contained proof that entries are in a stream, checked offline against a pinned
//! stream key (spec/receipts.md).
//!
//! A receipt holds a signed checkpoint, the entries it proves and the stream's key history up to
//! the checkpoint, each with its inclusion proof, and optionally RFC 3161 timestamp tokens over
//! the checkpoint. [`verify`] checks everything but the tokens, which need the verifier's pinned
//! timestamp authorities (`tenbri-anchor`); it hands them back unchecked.

use tenbri_core::canon::{self, Value};
use tenbri_core::{Chain, Code, Entry, Error, Kind, encoding};

use crate::checkpoint::{Checkpoint, Note, base64, unbase64};
use crate::tree::{Hash, inclusion_proof, verify_inclusion};

/// The receipt format version, the member `v`.
pub const VERSION: u64 = 1;

fn bad(detail: impl Into<String>) -> Error {
    Error::new(Code::BadReceipt, detail)
}

/// Makes a receipt. `note` is a signed checkpoint, `hashes` the stream's entry hashes from seq 1
/// to at least its size, `entries` the stored lines to prove, each with its seq, which must hold
/// the stream's genesis entry and every key entry up to the checkpoint's size; `rfc3161` are
/// timestamp responses over the checkpoint's text. `None` if `note` does not parse or an entry is
/// not covered by it.
pub fn build(
    note: &[u8],
    hashes: &[Hash],
    entries: &[(u64, &[u8])],
    rfc3161: &[Vec<u8>],
) -> Option<Vec<u8>> {
    let size = Note::parse(note).ok()?.checkpoint.size;
    let leaves = hashes.get(..usize::try_from(size).ok()?)?;
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|(seq, _)| *seq);
    sorted.dedup_by_key(|(seq, _)| *seq);
    let mut items = vec![];
    for (seq, line) in sorted {
        let proof = inclusion_proof(leaves, seq.checked_sub(1)?)?;
        items.push(Value::Obj(vec![
            ("entry".into(), canon::parse(line).ok()?),
            (
                "proof".into(),
                Value::Arr(proof.iter().map(|h| Value::Str(hash_str(h))).collect()),
            ),
        ]));
    }
    let mut members = vec![
        (
            "checkpoint".into(),
            Value::Str(String::from_utf8(note.to_vec()).ok()?),
        ),
        ("entries".into(), Value::Arr(items)),
        ("v".into(), Value::Int(VERSION as i64)),
    ];
    if !rfc3161.is_empty() {
        let tokens = rfc3161.iter().map(|t| Value::Str(base64(t))).collect();
        members.insert(2, ("rfc3161".into(), Value::Arr(tokens)));
    }
    let mut out = canon::to_vec(&Value::Obj(members));
    out.push(b'\n');
    Some(out)
}

/// A receipt that verified.
#[derive(Clone, Debug)]
pub struct Verified {
    /// The checkpoint every entry is proved against.
    pub checkpoint: Checkpoint,
    /// The note text the checkpoint's signatures and timestamp tokens cover.
    pub text: String,
    /// Every entry in the receipt, in seq order: the ones it was made for and the key history.
    pub entries: Vec<Entry>,
    /// The RFC 3161 timestamp responses, as DER, not yet checked.
    pub rfc3161: Vec<Vec<u8>>,
}

impl Verified {
    /// The entries the receipt was made for: all but the key entries, or all of them if the
    /// receipt holds only key entries.
    pub fn proved(&self) -> Vec<&Entry> {
        let not_keys: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| e.kind != Kind::Key)
            .collect();
        if not_keys.is_empty() {
            self.entries.iter().collect()
        } else {
            not_keys
        }
    }
}

/// Checks a receipt against `pin`, the fingerprint (`sha256:…`) of the stream's genesis key, with
/// no network and no access to the stream, in the order of spec/receipts.md, section 3. Returns
/// the first failure; its detail names the entry's seq where there is one.
pub fn verify(bytes: &[u8], pin: &str) -> Result<Verified, Error> {
    let value = canon::parse(bytes).map_err(|e| bad(format!("not a receipt: {e}")))?;
    let Value::Obj(members) = &value else {
        return Err(bad("not a JSON object"));
    };
    if let Some((k, _)) = members
        .iter()
        .find(|(k, _)| !["v", "checkpoint", "entries", "rfc3161"].contains(&k.as_str()))
    {
        return Err(bad(format!("unknown member `{k}`")));
    }
    if value.get("v") != Some(&Value::Int(VERSION as i64)) {
        return Err(bad("`v` is not 1"));
    }
    let Some(Value::Str(note)) = value.get("checkpoint") else {
        return Err(bad("`checkpoint` is not a string"));
    };
    let rfc3161 = match value.get("rfc3161") {
        None => vec![],
        Some(Value::Arr(a)) if !a.is_empty() => a
            .iter()
            .map(|t| match t {
                Value::Str(s) => unbase64(s),
                _ => None,
            })
            .collect::<Option<_>>()
            .ok_or_else(|| bad("`rfc3161` holds something other than base64"))?,
        Some(_) => return Err(bad("`rfc3161` is not a non-empty array")),
    };
    let items = match value.get("entries") {
        Some(Value::Arr(a)) if !a.is_empty() => a,
        _ => return Err(bad("`entries` is not a non-empty array")),
    };
    let items = items
        .iter()
        .map(item_parts)
        .collect::<Result<Vec<_>, _>>()?;
    let note = Note::parse(note.as_bytes())?;
    let cp = note.checkpoint.clone();

    let mut chain = Chain::new(Some(pin));
    let mut entries = vec![];
    for (line, proof, seq) in items {
        let at = |e: Error| Error::new(e.code, format!("seq {seq}: {}", e.detail));
        if entries.is_empty() && seq != 1 {
            return Err(bad(
                "the first entry is not the genesis entry: a receipt holds the key history from seq 1",
            ));
        }
        let checked = chain.check_detached(&line).map_err(at)?;
        if seq == 1 && checked.entry.stream != cp.origin {
            return Err(at(Error::new(
                Code::WrongStream,
                format!("the checkpoint is for {}", cp.origin),
            )));
        }
        let leaf = encoding::prefixed::<32>(&checked.hash, "sha256:").expect("an entry hash");
        if !verify_inclusion(seq - 1, cp.size, &leaf, &proof, &cp.root) {
            return Err(at(Error::new(
                Code::BadProof,
                format!(
                    "not included in the checkpoint at size {} (wrong proof, or the entry was changed)",
                    cp.size
                ),
            )));
        }
        entries.push(chain.apply(checked));
    }
    if let Some(b) = chain.invalidated() {
        return Err(Error::new(
            b.error.code,
            format!("seq {}: {}", b.seq, b.error.detail),
        ));
    }
    note.check_signer(&chain)?;
    Ok(Verified {
        text: note.text().to_owned(),
        checkpoint: cp,
        entries,
        rfc3161,
    })
}

/// An entry's stored line, its inclusion proof and its seq (0 if it has none).
fn item_parts(item: &Value) -> Result<(Vec<u8>, Vec<Hash>, u64), Error> {
    if item.keys().any(|k| k != "entry" && k != "proof") {
        return Err(bad(
            "an entry item has members other than `entry` and `proof`",
        ));
    }
    let entry @ Value::Obj(_) = item
        .get("entry")
        .ok_or_else(|| bad("an item has no `entry`"))?
    else {
        return Err(bad("an `entry` is not an object"));
    };
    let Some(Value::Arr(proof)) = item.get("proof") else {
        return Err(bad("an item has no `proof` array"));
    };
    let proof = proof
        .iter()
        .map(|h| match h {
            Value::Str(s) => encoding::prefixed::<32>(s, "sha256:"),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| bad("a proof hash is not sha256:<64 hex>"))?;
    let seq = match entry.get("seq") {
        Some(Value::Int(s)) if *s > 0 => *s as u64,
        _ => 0,
    };
    Ok((canon::to_vec(entry), proof, seq))
}

fn hash_str(h: &Hash) -> String {
    format!("sha256:{}", encoding::hex(h))
}
