//! Stream keys in a PKCS#11 token, against a real module when `TENBRI_TEST_PKCS11_MODULE`,
//! `TENBRI_TEST_PKCS11_TOKEN` and `TENBRI_TEST_PKCS11_PIN` are set (SoftHSM in CI).
#![cfg(feature = "pkcs11")]

use std::path::PathBuf;
use std::sync::Arc;

use tenbri_core::sign::SigningKey;
use tenbri_keys::pkcs11::Token;
use tenbri_keys::{Backend, Key, KeyStore};
use zeroize::Zeroizing;

/// The token under test, if this run has one.
fn token() -> Option<Arc<Token>> {
    let var = |k: &str| std::env::var(format!("TENBRI_TEST_PKCS11_{k}")).ok();
    let (Some(module), Some(label), Some(pin)) = (var("MODULE"), var("TOKEN"), var("PIN")) else {
        eprintln!("TENBRI_TEST_PKCS11_* not set: no PKCS#11 token in this run");
        return None;
    };
    Some(Token::new(
        PathBuf::from(module),
        label,
        Zeroizing::new(pin),
    ))
}

#[test]
fn a_token_generates_keeps_and_signs_with_the_stream_key() {
    let Some(token) = token() else { return };
    let sk = token.new_stream().unwrap();
    let msg = b"tenbri/entry/v1\0{}";
    let sig = sk.sign(msg).unwrap();
    sk.verifying_key().verify_strict(msg, &sig).unwrap();

    let tmp = std::env::temp_dir().join(format!("tenbri-pkcs11-{}", std::process::id()));
    let (keys, stream) = (tmp.join("keys"), tmp.join("stream"));
    std::fs::create_dir_all(&stream).unwrap();
    let id = tenbri_core::sign::stream_id(&sk.verifying_key());
    let ks = KeyStore::open(&keys, &stream, &id).unwrap();
    assert!(
        ks.save(&sk, Backend::File).is_err(),
        "no file for a token's key"
    );
    let local = Key::new_stream().unwrap();
    assert!(
        ks.save(&local, Backend::Pkcs11).is_err(),
        "a local key is no token's"
    );
    ks.save(&sk, Backend::Pkcs11).unwrap();
    assert!(
        std::fs::read_dir(ks.dir())
            .unwrap()
            .all(|e| e.unwrap().path().extension().unwrap() == "json"),
        "only its description is on disk"
    );

    // Loaded again through the store, it is the token's key, found by its id.
    assert!(ks.load(&sk.id).is_err(), "no token configured");
    let ks = ks.with_token(token.clone());
    let again = ks.load(&sk.id).unwrap();
    assert_eq!(again.public(), sk.public());
    let sig = again.sign(msg).unwrap();
    sk.verifying_key().verify_strict(msg, &sig).unwrap();

    // A description whose public key is not the token's key is refused.
    let other = SigningKey::from_bytes(&[7; 32]);
    assert!(
        token
            .key(&sk.id, &other.verifying_key())
            .is_err_and(|e| e.to_string().contains("not the one described"))
    );
    assert!(
        token
            .key("stream:000000000000", &other.verifying_key())
            .is_err()
    );
    ks.delete(&sk.id).unwrap();
    std::fs::remove_dir_all(&tmp).unwrap();
}

#[test]
fn a_token_is_opened_only_when_a_key_is_asked_for() {
    let t = Token::new(
        PathBuf::from("/nonexistent/libpkcs11.so"),
        "none".into(),
        Zeroizing::new("0000".into()),
    );
    assert!(
        t.new_stream()
            .is_err_and(|e| e.to_string().contains("/nonexistent/libpkcs11.so"))
    );
}
