//! Checkpoints: C2SP signed notes (c2sp.org/signed-note, c2sp.org/tlog-checkpoint) over the
//! Merkle root of a stream's first entries, signed by a session key (spec/checkpoints.md).

use sha2::{Digest, Sha256};
use tenbri_core::canon::MAX_INT;
use tenbri_core::sign::{Signature, Signer, SigningKey, VerifyingKey};
use tenbri_core::{Broken, Chain, Code, Error, Role, is_stream_id};

use crate::tree::{Hash, consistency_proof, root, verify_consistency};

/// The writer checkpoints after this many entries since the last checkpoint...
pub const EVERY_ENTRIES: u64 = 1000;
/// ...or this many milliseconds, whichever comes first.
pub const EVERY_MS: u64 = 60_000;
/// Signature lines a note may carry, the log's and any cosigners'.
pub const MAX_SIGNATURES: usize = 64;
/// The C2SP signature type of an Ed25519 note signature.
const ED25519: u8 = 0x01;

/// Whether a checkpoint is due: [`EVERY_ENTRIES`] new entries, or any new entry and [`EVERY_MS`].
pub fn due(entries_since: u64, ms_since: u64) -> bool {
    entries_since >= EVERY_ENTRIES || (entries_since > 0 && ms_since >= EVERY_MS)
}

/// The store key of the checkpoint at `size`: `checkpoints/` and the size, zero-padded to 12
/// digits, with `.note`, as batches are named.
pub fn key(size: u64) -> String {
    format!("checkpoints/{size:012}.note")
}

/// The C2SP key ID: the first four bytes of SHA-256(name || 0x0A || 0x01 || public key).
pub fn key_id(name: &str, key: &VerifyingKey) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([b'\n', ED25519]);
    h.update(key.as_bytes());
    h.finalize()[..4].try_into().expect("4 bytes")
}

/// A stream's size and Merkle root at that size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    /// The stream id, `tnb1:…`: the note's origin line and its signature's key name.
    pub origin: String,
    pub size: u64,
    pub root: Hash,
}

impl Checkpoint {
    /// The checkpoint of `stream` over `hashes`, the entry hashes from seq 1 in order.
    pub fn new(stream: &str, hashes: &[Hash]) -> Self {
        Checkpoint {
            origin: stream.to_owned(),
            size: hashes.len() as u64,
            root: root(hashes),
        }
    }

    /// The note text: origin, size and base64 root, one per line.
    pub fn text(&self) -> String {
        format!("{}\n{}\n{}\n", self.origin, self.size, base64(&self.root))
    }

    /// The signed note, as stored under [`key`]. `session` is the writer's current session key.
    pub fn sign(&self, session: &SigningKey) -> Vec<u8> {
        let text = self.text();
        let mut sig = key_id(&self.origin, &session.verifying_key()).to_vec();
        sig.extend(session.sign(text.as_bytes()).to_bytes());
        format!("{text}\n\u{2014} {} {}\n", self.origin, base64(&sig)).into_bytes()
    }
}

/// What the writer calls: the signed checkpoint of `stream` over its first `hashes.len()` entry
/// hashes, by the current session key.
pub fn sign(stream: &str, hashes: &[Hash], session: &SigningKey) -> Vec<u8> {
    Checkpoint::new(stream, hashes).sign(session)
}

/// A parsed signed note whose signatures are not yet checked.
#[derive(Clone, Debug)]
pub struct Note {
    pub checkpoint: Checkpoint,
    text: String,
    /// Key name, key ID and signature bytes of each signature line.
    sigs: Vec<(String, [u8; 4], Vec<u8>)>,
}

fn bad(detail: impl Into<String>) -> Error {
    Error::new(Code::BadCheckpoint, detail)
}

impl Note {
    /// Parses a stored checkpoint. Malformed notes fail with `bad_checkpoint`.
    pub fn parse(bytes: &[u8]) -> Result<Note, Error> {
        let s = std::str::from_utf8(bytes).map_err(|_| bad("not UTF-8"))?;
        if s.chars().any(|c| c < ' ' && c != '\n') {
            return Err(bad("a control character"));
        }
        let (text, sigs) = s
            .rsplit_once("\n\n")
            .ok_or_else(|| bad("no blank line before the signatures"))?;
        let text = format!("{text}\n");
        let lines: Vec<&str> = text.lines().collect();
        let [origin, size, root] = lines[..] else {
            return Err(bad(
                "the text is not exactly origin, size and root (no extension lines)",
            ));
        };
        if !is_stream_id(origin) {
            return Err(bad(format!("origin {origin:?} is not a stream id")));
        }
        let size = size
            .parse::<u64>()
            .ok()
            .filter(|n| *n <= MAX_INT as u64 && n.to_string() == size)
            .ok_or_else(|| bad(format!("size {size:?} is not a decimal integer")))?;
        let root = unbase64(root)
            .and_then(|b| <Hash>::try_from(b).ok())
            .ok_or_else(|| bad("the root is not 32 bytes of canonical base64"))?;
        let sigs = sigs
            .strip_suffix('\n')
            .ok_or_else(|| bad("no final line feed"))?
            .split('\n')
            .map(|l| {
                let (name, sig) = l
                    .strip_prefix("\u{2014} ")
                    .and_then(|l| l.split_once(' '))
                    .ok_or_else(|| bad(format!("{l:?} is not a signature line")))?;
                if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c == '+') {
                    return Err(bad(format!("key name {name:?}")));
                }
                let sig = unbase64(sig)
                    .filter(|b| b.len() > 4)
                    .ok_or_else(|| bad("a signature is not canonical base64"))?;
                Ok((
                    name.to_owned(),
                    sig[..4].try_into().unwrap(),
                    sig[4..].to_vec(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if sigs.len() > MAX_SIGNATURES {
            return Err(bad("too many signatures"));
        }
        Ok(Note {
            checkpoint: Checkpoint {
                origin: origin.to_owned(),
                size,
                root,
            },
            text,
            sigs,
        })
    }

    /// The note text the signatures cover.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// `None` if the note has no signature line for `key` under the origin's name, else whether
    /// that signature verifies (strictly, as entry signatures do).
    pub fn signed_by(&self, key: &VerifyingKey) -> Option<bool> {
        let id = key_id(&self.checkpoint.origin, key);
        let mut lines = self
            .sigs
            .iter()
            .filter(|(n, i, _)| *n == self.checkpoint.origin && *i == id)
            .peekable();
        lines.peek()?;
        Some(lines.all(|(_, _, sig)| {
            <[u8; 64]>::try_from(&sig[..]).is_ok_and(|b| {
                key.verify_strict(self.text.as_bytes(), &Signature::from_bytes(&b))
                    .is_ok()
            })
        }))
    }

    /// Checks `chain`, a stream read and verified to its end with entry hashes `hashes`, against
    /// this checkpoint, in this order: same stream, not truncated behind it, signed by a session
    /// key the stream certified by its size and had not revoked by then, and the stream's first
    /// `size` entries have its root. Returns the stream's current checkpoint.
    pub fn check(&self, chain: &Chain, hashes: &[Hash]) -> Result<Checkpoint, Broken> {
        let cp = &self.checkpoint;
        let at = |seq: u64, code: Code, detail: String| Broken {
            seq,
            error: Error::new(code, detail),
        };
        if chain.stream() != Some(cp.origin.as_str()) {
            return Err(at(
                1,
                Code::WrongStream,
                format!("the checkpoint is for {}", cp.origin),
            ));
        }
        let len = hashes.len() as u64;
        if len < cp.size {
            return Err(at(
                len + 1,
                Code::Truncated,
                format!(
                    "the checkpoint covers {} entries, the stream has {len}",
                    cp.size
                ),
            ));
        }
        self.check_signer(chain).map_err(|e| Broken {
            seq: cp.size,
            error: e,
        })?;
        let now = Checkpoint::new(&cp.origin, hashes);
        let proof = consistency_proof(hashes, cp.size).expect("size <= len");
        if !verify_consistency(cp.size, now.size, &cp.root, &now.root, &proof) {
            return Err(at(
                cp.size,
                Code::Fork,
                format!(
                    "entries 1 to {} do not have the checkpoint's root: the stream was rewritten at or before seq {}",
                    cp.size, cp.size
                ),
            ));
        }
        Ok(now)
    }

    fn check_signer(&self, chain: &Chain) -> Result<(), Error> {
        let size = self.checkpoint.size;
        let mut first_err = None;
        for (id, k) in chain.keys() {
            let Some(ok) = self.signed_by(&k.public) else {
                continue;
            };
            let err = if k.role != Role::Session {
                Error::new(
                    Code::SignerNotAllowed,
                    format!("checkpoint signed by stream key {id}"),
                )
            } else if k.certified_at > size {
                Error::new(
                    Code::SignerNotAllowed,
                    format!(
                        "checkpoint signer {id} is certified at seq {}, after it",
                        k.certified_at
                    ),
                )
            } else if k.revoked_from.is_some_and(|f| f <= size) {
                Error::new(
                    Code::KeyRevoked,
                    format!("checkpoint signer {id} is revoked"),
                )
            } else if !ok {
                bad(format!("the signature by {id} does not verify"))
            } else {
                return Ok(());
            };
            first_err.get_or_insert(err);
        }
        Err(first_err.unwrap_or_else(|| {
            Error::new(
                Code::UnknownSigner,
                "no signature by a key the stream certified",
            )
        }))
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with `=` padding (RFC 4648, section 4).
pub fn base64(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            s.push(if i <= c.len() {
                B64[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    s
}

/// Decodes canonical base64 only: padded, no unused bits set (RFC 4648, section 3.5).
pub fn unbase64(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 4 != 0 {
        return None;
    }
    let pad = s.iter().rev().take_while(|&&c| c == b'=').count();
    if pad > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut n = 0u32;
    for (i, &c) in s[..s.len() - pad].iter().enumerate() {
        n = n << 6 | B64.iter().position(|&x| x == c)? as u32;
        if i % 4 == 3 {
            out.extend_from_slice(&n.to_be_bytes()[1..]);
            n = 0;
        }
    }
    match pad {
        1 if n & 3 == 0 => out.extend_from_slice(&(n >> 2).to_be_bytes()[2..]),
        2 if n & 15 == 0 => out.push((n >> 4) as u8),
        0 => {}
        _ => return None,
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_rejects_non_canonical() {
        for n in 0..40u8 {
            let b: Vec<u8> = (0..n).collect();
            assert_eq!(unbase64(&base64(&b)), Some(b));
        }
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(unbase64("Zm9="), None, "unused bits set");
        assert_eq!(unbase64("Zm8"), None, "unpadded");
        assert_eq!(unbase64("Z==="), None);
        assert_eq!(unbase64("Zm8=Zm8="), None, "padding inside");
    }

    /// The C2SP signed-note spec's own example: its key ID and its signature.
    #[test]
    fn c2sp_example_verifies() {
        let vkey = unbase64("AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k").unwrap();
        let key = VerifyingKey::from_bytes(&vkey[1..].try_into().unwrap()).unwrap();
        assert_eq!(key_id("example.com/foo", &key), [0x53, 0x0d, 0x90, 0x3a]);
        let sig = unbase64("Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=").unwrap();
        assert_eq!(sig[..4], [0x53, 0x0d, 0x90, 0x3a]);
        let sig = Signature::from_bytes(&sig[4..].try_into().unwrap());
        assert!(
            key.verify_strict(b"This is an example message.\n", &sig)
                .is_ok()
        );
    }
}
