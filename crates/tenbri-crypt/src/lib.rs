//! Tenbri blob encryption, per-subject data and digest keys, and erasure (spec/privacy.md).
//!
//! Content stays out of the chain. An entry's body is sealed with XChaCha20-Poly1305 under a data
//! key of its `subject` (or of the tenant, the stream, when it has none) and stored as a blob
//! addressed by the SHA-256 of its ciphertext; its input digests are HMAC-SHA-256 under a key
//! derived from the same data key with HKDF. Deleting the data key ([`DataKeys::erase`]) makes the
//! bodies unreadable and the digests unconfirmable, and every chain, checkpoint and receipt still
//! verifies, because none of them depends on the key.
//!
//! The functions at the top level are the format: pure, no I/O, checked by the vectors in
//! spec/vectors/privacy.json. [`DataKeys`] is the local key store (one file per subject and key
//! epoch, owner-only) and puts and reads blobs through any [`tenbri_store::Store`].

mod keystore;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tenbri_core::encoding::{hex, prefixed};
use zeroize::Zeroizing;

pub use keystore::{DataKeys, Epoch, Error, Held, epoch_note, erasure_note};

/// A data key: 32 random bytes, one per subject (or tenant) and key epoch.
pub type DataKey = [u8; 32];

/// The prefix of a body address.
pub const ADDRESS_PREFIX: &str = "blob:ct-sha256:";
/// The prefix of an input digest.
pub const DIGEST_PREFIX: &str = "hmac-sha256:";
/// The bytes of the random nonce at the start of every blob.
pub const NONCE_LEN: usize = 24;

const BLOB_INFO: &[u8] = b"tenbri/blob/v1";
const DIGEST_INFO: &[u8] = b"tenbri/digest/v1";

fn derive(data_key: &DataKey, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, data_key)
        .expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA-256 length");
    out
}

/// The key that seals blobs: HKDF-SHA-256 of the data key, no salt, info `tenbri/blob/v1`.
pub fn blob_key(data_key: &DataKey) -> Zeroizing<[u8; 32]> {
    derive(data_key, BLOB_INFO)
}

/// The key of input digests: HKDF-SHA-256 of the data key, no salt, info `tenbri/digest/v1`. It
/// is what an operator hands an auditor to confirm one subject's inputs, without opening bodies.
pub fn digest_key(data_key: &DataKey) -> Zeroizing<[u8; 32]> {
    derive(data_key, DIGEST_INFO)
}

/// `tenbri/blob/v1 || 0x00 || stream id`: a blob opens only in the stream it was sealed for.
fn aad(stream: &str) -> Vec<u8> {
    let mut a = BLOB_INFO.to_vec();
    a.push(0);
    a.extend_from_slice(stream.as_bytes());
    a
}

fn cipher(data_key: &DataKey) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new((&*blob_key(data_key)).into())
}

/// Seals `plaintext` for `stream`: `nonce || XChaCha20-Poly1305(blob key, nonce, plaintext, aad)`.
/// The nonce must be random and never reused with the same data key; [`DataKeys`] draws it.
pub fn seal(
    data_key: &DataKey,
    stream: &str,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let ct = cipher(data_key)
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: &aad(stream),
            },
        )
        .expect("XChaCha20-Poly1305 seals any length that fits in memory");
    let mut blob = nonce.to_vec();
    blob.extend(ct);
    blob
}

/// Opens a blob of `stream` sealed under `data_key`; `None` if the key is not the one that sealed
/// it, or the blob was changed.
pub fn open(data_key: &DataKey, stream: &str, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    cipher(data_key)
        .decrypt(
            &XNonce::try_from(nonce).ok()?,
            Payload {
                msg: ct,
                aad: &aad(stream),
            },
        )
        .ok()
        .map(Zeroizing::new)
}

/// A blob's body address: `blob:ct-sha256:` and the hex SHA-256 of the whole blob, nonce included.
/// It reveals nothing about the content.
pub fn address(blob: &[u8]) -> String {
    format!("{ADDRESS_PREFIX}{}", hex(&Sha256::digest(blob)))
}

/// Where a blob is stored in a stream: `blobs/ct-sha256/<2 hex>/<62 hex>`; `None` if `address` is
/// not a body address.
pub fn blob_path(address: &str) -> Option<String> {
    prefixed::<32>(address, ADDRESS_PREFIX)?;
    let h = &address[ADDRESS_PREFIX.len()..];
    Some(format!("blobs/ct-sha256/{}/{}", &h[..2], &h[2..]))
}

/// An input digest: `hmac-sha256:` and the hex HMAC-SHA-256 of `content` under the digest key.
pub fn digest(data_key: &DataKey, content: &[u8]) -> String {
    let key = digest_key(data_key);
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_ref()).expect("HMAC takes any key length");
    mac.update(content);
    format!("{DIGEST_PREFIX}{}", hex(&mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_opens_and_refuses_the_wrong_key_stream_or_bytes() {
        let (k, other) = ([7u8; 32], [8u8; 32]);
        let blob = seal(&k, "tnb1:a", &[1; NONCE_LEN], b"refund approved");
        assert_eq!(&open(&k, "tnb1:a", &blob).unwrap()[..], b"refund approved");
        assert!(open(&other, "tnb1:a", &blob).is_none(), "wrong key");
        assert!(open(&k, "tnb1:b", &blob).is_none(), "other stream");
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&k, "tnb1:a", &bad).is_none(), "changed bytes");
        assert!(open(&k, "tnb1:a", &blob[..10]).is_none(), "truncated");
        assert_ne!(*blob_key(&k), *digest_key(&k));
        assert_ne!(digest(&k, b"x"), digest(&other, b"x"));
        let a = address(&blob);
        assert_eq!(
            blob_path(&a).unwrap(),
            format!("blobs/ct-sha256/{}/{}", &a[15..17], &a[17..])
        );
        assert!(blob_path("sha256:00").is_none());
    }
}
