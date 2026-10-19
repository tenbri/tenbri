//! Hashes and domain-separated Ed25519 signatures (spec/format-v1.md, section 6).

pub use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::canon::{self, Value};
use crate::encoding::{hex, prefixed};
use crate::entry::{Attestation, Entry};
use crate::error::{Code, Error};
use crate::head::Head;

/// Prefix of every entry signature's message.
pub const ENTRY_PREFIX: &[u8] = b"tenbri/entry/v1\0";
/// Prefix of every HEAD signature's message.
pub const HEAD_PREFIX: &[u8] = b"tenbri/head/v1\0";
/// Prefix of every attestation's message.
pub const ATTESTATION_PREFIX: &[u8] = b"tenbri/attestation/v1\0";

/// `sha256:` and the hex SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

/// The entry hash: the RFC 6962 leaf hash SHA-256(0x00 || line) of a stored line.
pub fn entry_hash(line: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(line);
    format!("sha256:{}", hex(&h.finalize()))
}

/// The key fingerprint verifiers pin: `sha256:` and the hex SHA-256 of the 32-byte public key.
pub fn fingerprint(key: &VerifyingKey) -> String {
    sha256(key.as_bytes())
}

/// The stream id a genesis key gives: `tnb1:` and the first 32 hex digits of its fingerprint.
pub fn stream_id(key: &VerifyingKey) -> String {
    format!("tnb1:{}", &fingerprint(key)["sha256:".len()..][..32])
}

/// `ed25519:` and the public key in hex.
pub fn encode_key(key: &VerifyingKey) -> String {
    format!("ed25519:{}", hex(key.as_bytes()))
}

/// Decodes `ed25519:<64 hex>`. Small-order and other weak keys are refused at verification.
pub fn decode_key(s: &str) -> Result<VerifyingKey, Error> {
    prefixed::<32>(s, "ed25519:")
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| Error::new(Code::InvalidField, format!("{s:?} is not an ed25519 key")))
}

fn encode_sig(sig: &Signature) -> String {
    format!("ed25519:{}", hex(&sig.to_bytes()))
}

/// The message signed with `prefix`: the prefix and the canonical value without `omit` members.
pub fn message(prefix: &[u8], value: &Value, omit: &[&str]) -> Vec<u8> {
    let mut v = value.clone();
    for k in omit {
        v.remove(k);
    }
    let mut msg = prefix.to_vec();
    msg.extend(canon::to_vec(&v));
    msg
}

/// Strict Ed25519 verification of `sig` (`ed25519:<128 hex>`) over `msg`.
pub fn verify(key: &VerifyingKey, msg: &[u8], sig: &str) -> Result<(), Error> {
    let bad = |d: &str| Error::new(Code::BadSignature, d.to_owned());
    let bytes = prefixed::<64>(sig, "ed25519:").ok_or_else(|| bad("malformed signature"))?;
    key.verify_strict(msg, &Signature::from_bytes(&bytes))
        .map_err(|_| bad("the signature does not verify"))
}

/// Signs `entry` with `key` (setting `sig`) and returns its stored line, without the line feed.
pub fn sign_entry(entry: &mut Entry, key: &SigningKey) -> Result<Vec<u8>, Error> {
    let value = canon::from_serialize(entry)?;
    entry.sig = encode_sig(&key.sign(&message(ENTRY_PREFIX, &value, &["sig"])));
    Ok(canon::to_vec(&canon::from_serialize(entry)?))
}

/// The members an attestation does not cover: those the writer fills, and the attestations.
pub const NOT_ATTESTED: [&str; 5] = ["seq", "prev", "signer", "sig", "attestations"];

/// An attestation by `key` over `entry` without [`NOT_ATTESTED`], so a principal can sign a draft
/// (with its `id`, `ts` and `stream` set) before a writer places it.
pub fn attest(entry: &Entry, key: &SigningKey) -> Result<Attestation, Error> {
    let value = canon::from_serialize(entry)?;
    let msg = message(ATTESTATION_PREFIX, &value, &NOT_ATTESTED);
    Ok(Attestation {
        key: encode_key(&key.verifying_key()),
        sig: encode_sig(&key.sign(&msg)),
    })
}

/// Signs `head` with `key` (setting `sig`) and returns its stored bytes.
pub fn sign_head(head: &mut Head, key: &SigningKey) -> Vec<u8> {
    let value = canon::from_serialize(head).expect("a HEAD holds only strings and integers");
    head.sig = encode_sig(&key.sign(&message(HEAD_PREFIX, &value, &["sig"])));
    canon::to_vec(&canon::from_serialize(head).expect("a HEAD holds only strings and integers"))
}
