//! Witness cosignatures (Experimental, feature `witness`): the stream's checkpoint key, C2SP
//! cosignatures (c2sp.org/tlog-cosignature) and the body of a tlog-witness `add-checkpoint`
//! request (c2sp.org/tlog-witness). No I/O; spec/checkpoints.md, section 6.
//!
//! A witness checks that each checkpoint it sees for a log is consistent with the last one it
//! cosigned, then cosigns it. A verifier that requires cosignatures from witnesses it pinned
//! catches a rewritten or forked stream even when the operator's host and keys are compromised:
//! the witnesses refuse to cosign a checkpoint that contradicts one they cosigned before.

use sha2::{Digest, Sha256};
use tenbri_core::sign::{Signature, Signer, SigningKey, VerifyingKey, decode_key, encode_key};
use tenbri_core::{Code, Entry, Error, Kind, encoding};

use crate::checkpoint::{Note, base64, unbase64};
use crate::receipt::Verified;
use crate::tree::Hash;

/// The member of a `key` entry's `ext` that certifies the stream's checkpoint key: the stream key
/// signs the entry, so it vouches for the key (`ed25519:<hex>`).
pub const EXT: &str = "checkpoint_key";
/// The C2SP signature type of an Ed25519 note signature.
const ED25519: u8 = 0x01;
/// The C2SP signature type of a timestamped Ed25519 cosignature (cosignature/v1).
const COSIGNATURE: u8 = 0x04;

fn bad(detail: impl Into<String>) -> Error {
    Error::new(Code::Unwitnessed, detail)
}

/// The C2SP key ID of a key of signature type `ty` named `name`.
fn key_id(name: &str, ty: u8, key: &VerifyingKey) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([b'\n', ty]);
    h.update(key.as_bytes());
    h.finalize()[..4].try_into().expect("4 bytes")
}

fn vkey(name: &str, ty: u8, key: &VerifyingKey) -> String {
    let mut k = vec![ty];
    k.extend(key.as_bytes());
    format!(
        "{name}+{}+{}",
        encoding::hex(&key_id(name, ty, key)),
        base64(&k)
    )
}

/// The verifier key a witness is configured with for the stream: the checkpoint key under the
/// stream id, `tnb1:…+<key ID>+<base64>` (c2sp.org/signed-note).
pub fn log_vkey(origin: &str, key: &VerifyingKey) -> String {
    vkey(origin, ED25519, key)
}

/// The `ext` of the `key` entry that certifies `key` as the stream's checkpoint key.
pub fn ext(key: &VerifyingKey) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert(EXT.into(), encode_key(key).into());
    m
}

/// The checkpoint key in force at seq `size`: the last one a `key` entry at or before `size`
/// certified. `entries` are verified entries in seq order (a stream's or a receipt's), so every
/// `key` entry among them is signed by the stream key.
pub fn checkpoint_key(entries: &[Entry], size: u64) -> Option<VerifyingKey> {
    entries
        .iter()
        .filter(|e| e.kind == Kind::Key && e.seq <= size)
        .filter_map(|e| e.ext.as_ref()?.get(EXT)?.as_str())
        .filter_map(|k| decode_key(k).ok())
        .next_back()
}

/// A witness a verifier pinned: its name and cosigning key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub name: String,
    pub key: VerifyingKey,
}

impl Witness {
    /// Parses a witness verifier key, `<name>+<key ID hex>+<base64 of 0x04 and the public key>`.
    pub fn parse(vkey: &str) -> Result<Witness, Error> {
        let fail = || {
            Error::new(
                Code::Parse,
                format!("{vkey:?} is not a witness key (name+id+base64)"),
            )
        };
        let mut parts = vkey.splitn(3, '+');
        let (Some(name), Some(_), Some(k)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(fail());
        };
        let k = unbase64(k).filter(|k| k.len() == 33 && k[0] == COSIGNATURE);
        let key = k
            .and_then(|k| VerifyingKey::from_bytes(&k[1..].try_into().ok()?).ok())
            .ok_or_else(fail)?;
        let w = Witness {
            name: name.to_owned(),
            key,
        };
        if name.is_empty() || name.chars().any(char::is_whitespace) || w.vkey() != vkey {
            return Err(fail());
        }
        Ok(w)
    }

    /// The key ID, in hex: the name of its cosignature files.
    pub fn key_id(&self) -> String {
        encoding::hex(&key_id(&self.name, COSIGNATURE, &self.key))
    }

    /// The verifier key, as [`Witness::parse`] reads it.
    pub fn vkey(&self) -> String {
        vkey(&self.name, COSIGNATURE, &self.key)
    }

    /// `None` if `note` has no cosignature line by this witness; else the time of its cosignature,
    /// or why it does not verify.
    pub fn cosigned(&self, note: &Note) -> Option<Result<u64, Error>> {
        let id = key_id(&self.name, COSIGNATURE, &self.key);
        let (_, _, sig) = note
            .sigs
            .iter()
            .find(|(n, i, _)| *n == self.name && *i == id)?;
        Some(
            <[u8; 72]>::try_from(&sig[..])
                .ok()
                .and_then(|s| {
                    let time = u64::from_be_bytes(s[..8].try_into().expect("8 bytes"));
                    let sig = Signature::from_bytes(&s[8..].try_into().expect("64 bytes"));
                    self.key
                        .verify_strict(message(note.text(), time).as_bytes(), &sig)
                        .is_ok()
                        .then_some(time)
                })
                .ok_or_else(|| bad(format!("the cosignature by {} does not verify", self.name))),
        )
    }
}

/// What a witness signs: c2sp.org/tlog-cosignature's message for note text `text` at `time`.
pub fn message(text: &str, time: u64) -> String {
    format!("cosignature/v1\ntime {time}\n{text}")
}

/// A cosignature line by witness `name` with `key` over note text `text`, at `time` seconds since
/// the Unix epoch.
pub fn cosign(name: &str, key: &SigningKey, text: &str, time: u64) -> String {
    let mut sig = key_id(name, COSIGNATURE, &key.verifying_key()).to_vec();
    sig.extend(time.to_be_bytes());
    sig.extend(key.sign(message(text, time).as_bytes()).to_bytes());
    format!("\u{2014} {name} {}\n", base64(&sig))
}

/// A witness that cosigned, and when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosigned {
    pub name: String,
    /// Seconds since the Unix epoch: the witness's time, not the writer's.
    pub time: u64,
}

/// Checks a verified receipt's checkpoint against witnesses the verifier pinned: a signature line
/// by the checkpoint key the receipt's key history certified MUST verify (`bad_checkpoint`), then
/// [`cosignatures`].
pub fn verify(r: &Verified, witnesses: &[Witness], need: usize) -> Result<Vec<Cosigned>, Error> {
    if let Some(k) = checkpoint_key(&r.entries, r.checkpoint.size) {
        if r.note.signed_by(&k) == Some(false) {
            return Err(Error::new(
                Code::BadCheckpoint,
                "the signature by the stream's checkpoint key does not verify",
            ));
        }
    }
    cosignatures(&r.note, witnesses, need)
}

/// The pinned `witnesses` that cosigned `note`: every cosignature by one of them MUST verify, and
/// at least `need` of them MUST have cosigned (`unwitnessed`).
pub fn cosignatures(
    note: &Note,
    witnesses: &[Witness],
    need: usize,
) -> Result<Vec<Cosigned>, Error> {
    let mut out = vec![];
    for w in witnesses {
        if let Some(t) = w.cosigned(note) {
            out.push(Cosigned {
                name: w.name.clone(),
                time: t?,
            });
        }
    }
    if out.len() < need {
        return Err(bad(format!(
            "{} of the {need} required witness cosignatures",
            out.len()
        )));
    }
    Ok(out)
}

/// The body of a tlog-witness `add-checkpoint` request: the size of the checkpoint the witness
/// last cosigned for this log, a consistency proof from it, and the signed note.
pub fn request(old: u64, proof: &[Hash], note: &[u8]) -> Vec<u8> {
    let mut b = format!("old {old}\n");
    for h in proof {
        b.push_str(&base64(h));
        b.push('\n');
    }
    b.push('\n');
    let mut b = b.into_bytes();
    b.extend_from_slice(note);
    b
}

/// The parts of an `add-checkpoint` body: old size, consistency proof and note. `None` if it is
/// malformed.
pub fn parse_request(body: &[u8]) -> Option<(u64, Vec<Hash>, &[u8])> {
    let end = body.windows(2).position(|w| w == b"\n\n")?;
    let head = std::str::from_utf8(&body[..end]).ok()?;
    let mut lines = head.split('\n');
    let old = lines.next()?.strip_prefix("old ")?;
    let old = old.parse().ok().filter(|n: &u64| n.to_string() == old)?;
    let proof = lines
        .map(|l| <Hash>::try_from(unbase64(l)?).ok())
        .collect::<Option<Vec<_>>>()?;
    Some((old, proof, &body[end + 2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vkeys_round_trip_and_request_parses() {
        let k = SigningKey::from_bytes(&[7; 32]);
        let w = Witness {
            name: "witness.example/w1".into(),
            key: k.verifying_key(),
        };
        assert_eq!(Witness::parse(&w.vkey()), Ok(w.clone()));
        assert!(Witness::parse(&w.vkey().replace("w1+", "w2+")).is_err());
        assert!(Witness::parse(&log_vkey("w", &w.key)).is_err(), "type 0x01");
        let body = request(3, &[[1; 32], [2; 32]], b"note\n\n- sig\n");
        assert_eq!(
            parse_request(&body),
            Some((3, vec![[1; 32], [2; 32]], &b"note\n\n- sig\n"[..]))
        );
        assert_eq!(parse_request(b"old 03\n\nx"), None);
    }
}
