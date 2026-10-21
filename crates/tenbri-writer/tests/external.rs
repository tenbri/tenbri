//! A stream key kept by an external signer (an HSM; here a double behind the same trait): it signs
//! the genesis, certifications, rotations and revocations, the host keeps only session keys, and
//! the stream verifies.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tenbri_core::sign::{Signature, Signer, SigningKey, VerifyingKey};
use tenbri_core::{Entry, KeyEvent, Kind};
use tenbri_keys::{Backend, External, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_store::LocalStore;
use tenbri_writer::{WriteError, Writer, now_ms, verify};

/// A signer that keeps its key to itself, counts what it signs, and can be made unreachable or
/// to answer with someone else's signature.
struct Double {
    key: SigningKey,
    signed: AtomicUsize,
    down: AtomicBool,
    lying: AtomicBool,
}

impl Double {
    fn new(seed: u8) -> Arc<Double> {
        Arc::new(Double {
            key: SigningKey::from_bytes(&[seed; 32]),
            signed: AtomicUsize::new(0),
            down: AtomicBool::new(false),
            lying: AtomicBool::new(false),
        })
    }
}

impl External for Double {
    fn public(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    fn sign(&self, msg: &[u8]) -> io::Result<Signature> {
        if self.down.load(Ordering::SeqCst) {
            return Err(io::Error::other("token unreachable"));
        }
        if self.lying.load(Ordering::SeqCst) {
            return Ok(SigningKey::from_bytes(&[0xee; 32]).sign(msg));
        }
        self.signed.fetch_add(1, Ordering::SeqCst);
        Ok(self.key.sign(msg))
    }
}

fn signer_of(e: &Entry) -> &str {
    &e.signer
}

#[tokio::test]
async fn an_external_stream_key_certifies_rotates_and_revokes() {
    let dir = std::env::temp_dir().join(format!("tenbri-external-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (stream_dir, keys_dir) = (dir.join("stream"), dir.join("keys"));
    std::fs::create_dir_all(&stream_dir).unwrap();
    let store = LocalStore::open(&stream_dir).unwrap();

    let (hsm1, hsm2) = (Double::new(1), Double::new(2));
    let sk = Key::external_stream(hsm1.clone()).unwrap();
    let pin = sk.fingerprint();
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    let first_session = session.id.clone();

    // The host's key store holds the session keys; a token's key cannot go in a file.
    let id = tenbri_core::sign::stream_id(&sk.verifying_key());
    let ks = KeyStore::open(&keys_dir, &stream_dir, &id).unwrap();
    assert!(ks.save(&sk, Backend::File).is_err());
    ks.save(&session, Backend::File).unwrap();

    // Genesis and the first certification: signed by the token.
    let mut w = Writer::create(store.clone(), &sk, session).await.unwrap();
    assert_eq!(
        hsm1.signed.load(Ordering::SeqCst),
        3,
        "genesis, its HEAD, a certify"
    );
    w.append(Entry::new(Kind::Note)).await.unwrap();

    // Rotate to a second token key, certify a session with it, revoke the first session.
    let sk2 = Key::external_stream(hsm2.clone()).unwrap();
    let rotated = w.rotate(&sk, &sk2).await.unwrap();
    assert_eq!(signer_of(&rotated), sk.id);
    let certified = w
        .certify_session(
            &sk2,
            Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(signer_of(&certified), sk2.id);
    let from = w.chain().seq() + 1;
    let revoked = w.revoke(&sk2, &first_session, from).await.unwrap();
    assert_eq!(signer_of(&revoked), sk2.id);
    assert!(matches!(
        revoked.key,
        Some(KeyEvent::Revoke { ref id, .. }) if *id == first_session
    ));
    w.append(Entry::new(Kind::Note)).await.unwrap();

    // A token out of reach: the key event fails as a write, and nothing is written.
    let before = w.chain().seq();
    hsm2.down.store(true, Ordering::SeqCst);
    let s = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    assert!(matches!(
        w.certify_session(&sk2, s.clone()).await,
        Err(WriteError::Io(_))
    ));
    // A token answering with a signature that is not its key's: refused before it is used.
    hsm2.down.store(false, Ordering::SeqCst);
    hsm2.lying.store(true, Ordering::SeqCst);
    assert!(matches!(
        w.certify_session(&sk2, s.clone()).await,
        Err(WriteError::Io(e)) if e.to_string().contains("does not verify")
    ));
    hsm2.lying.store(false, Ordering::SeqCst);
    assert_eq!(w.chain().seq(), before);
    w.certify_session(&sk2, s).await.unwrap();
    w.append(Entry::new(Kind::Note)).await.unwrap();
    let n = w.chain().seq();
    drop(w);

    let r = verify(&store, Some(&pin)).await.unwrap();
    assert_eq!((r.broken, r.entries, r.pinned), (None, n, true));
    assert!(hsm2.signed.load(Ordering::SeqCst) >= 3);
    std::fs::remove_dir_all(&dir).unwrap();
}
