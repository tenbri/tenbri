//! Erasure end to end: bodies and digests for two subjects in a real stream, one subject erased,
//! and everything that does not need its key still verifies.

use std::fs;
use std::path::PathBuf;

use tenbri_core::{Action, Entry, Input, Kind, Principal, PrincipalKind, sign};
use tenbri_crypt::{DataKeys, Error, erasure_note};
use tenbri_keys::{Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_merkle::checkpoint;
use tenbri_store::{LocalStore, Store};
use tenbri_writer::{Writer, now_ms, verify};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tenbri-crypt-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn decision(subject: &str, body: String, digest: String) -> Entry {
    Entry {
        phase: Some(tenbri_core::Phase::Intent),
        source: Some(tenbri_core::Source::Sdk),
        principal: Some(Principal {
            kind: PrincipalKind::Agent,
            id: "support-assistant".into(),
        }),
        action: Some(Action {
            r#type: "reply_ticket".into(),
            target: Some("zendesk:ticket/4821".into()),
        }),
        subject: Some(subject.into()),
        inputs: Some(vec![Input {
            r#ref: "ticket:4821".into(),
            version: "3".into(),
            digest,
        }]),
        body: Some(body),
        ..Entry::new(Kind::Decision)
    }
}

#[tokio::test]
async fn erasure_keeps_the_stream_verifying_and_the_body_unreadable() {
    let root = tmp("erasure");
    let (stream_dir, keys_dir) = (root.join("stream"), root.join("keys"));
    fs::create_dir_all(&stream_dir).unwrap();
    let store = LocalStore::open(&stream_dir).unwrap();
    let sk = Key::new_stream().unwrap();
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    let stream = sign::stream_id(&sk.signing.verifying_key());
    let pin = sk.fingerprint();
    let ks = KeyStore::open(&keys_dir, &stream_dir, &stream).unwrap();
    let data = DataKeys::open(&ks).unwrap();
    let mut w = Writer::create(store.clone(), &sk, session.clone())
        .await
        .unwrap();

    let mut written = vec![];
    for (subject, text) in [
        ("cust_42", "Refund of 40 EUR approved"),
        ("cust_7", "Hello"),
    ] {
        let body = data
            .seal_body(&store, Some(subject), text.as_bytes())
            .await
            .unwrap();
        let digest = data.digest(Some(subject), b"ticket text").unwrap();
        written.push(w.append(decision(subject, body, digest)).await.unwrap());
    }
    // The address and the digest reveal nothing: same content, other subject, other values.
    assert_ne!(
        written[0].inputs.as_ref().unwrap()[0].digest,
        written[1].inputs.as_ref().unwrap()[0].digest
    );
    assert_eq!(
        &data.open_body(&store, &written[0]).await.unwrap().unwrap()[..],
        b"Refund of 40 EUR approved"
    );
    assert!(
        data.confirm(
            Some("cust_42"),
            b"ticket text",
            &written[0].inputs.as_ref().unwrap()[0].digest
        )
        .unwrap()
    );

    // A checkpoint taken before the erasure, as an auditor would hold it.
    let note = checkpoint::sign(&stream, w.hashes(), &session.signing);
    store
        .put_if_absent(&checkpoint::key(w.hashes().len() as u64), &note)
        .await
        .unwrap();

    assert_eq!(data.erase(Some("cust_42")).unwrap(), 1);
    let by = Principal {
        kind: PrincipalKind::Person,
        id: "dpo@example.com".into(),
    };
    let recorded = w
        .append(erasure_note(Some("cust_42"), "dsr:2026-1042", Some(by)))
        .await
        .unwrap();
    assert_eq!(recorded.subject.as_deref(), Some("cust_42"));

    let r = verify(&store, Some(&pin)).await.unwrap();
    assert!(r.broken.is_none(), "{:?}", r.broken);
    assert_eq!((r.entries, r.checkpoint), (5, Some(4)));

    match data.open_body(&store, &written[0]).await {
        Err(e @ Error::NoKey(_)) => assert!(e.to_string().contains("erased"), "{e}"),
        r => panic!("expected NoKey, got {r:?}"),
    }
    assert!(matches!(
        data.confirm(Some("cust_42"), b"ticket text", "hmac-sha256:00"),
        Err(Error::NoKey(_))
    ));
    // The other subject is untouched.
    assert_eq!(
        &data.open_body(&store, &written[1]).await.unwrap().unwrap()[..],
        b"Hello"
    );

    // A key made for the same handle after erasure never opens the old body.
    data.digest(Some("cust_42"), b"new").unwrap();
    match data.open_body(&store, &written[0]).await {
        Err(e @ Error::WrongKey(..)) => assert!(e.to_string().contains("no data key"), "{e}"),
        r => panic!("expected WrongKey, got {r:?}"),
    }
    fs::remove_dir_all(&root).unwrap();
}

#[tokio::test]
async fn rotation_keeps_old_epochs_and_tampering_is_caught() {
    let root = tmp("rotation");
    let (stream_dir, keys_dir) = (root.join("stream"), root.join("keys"));
    fs::create_dir_all(&stream_dir).unwrap();
    let store = LocalStore::open(&stream_dir).unwrap();
    let stream = "tnb1:0123456789abcdef0123456789abcdef";
    let data = DataKeys::open(&KeyStore::open(&keys_dir, &stream_dir, stream).unwrap()).unwrap();

    let old = data.seal_body(&store, None, b"tenant body").await.unwrap();
    let old_digest = data.digest(None, b"x").unwrap();
    assert_eq!(data.rotate(None).unwrap(), 2);
    let new_digest = data.digest(None, b"x").unwrap();
    assert_ne!(old_digest, new_digest);
    assert!(data.confirm(None, b"x", &old_digest).unwrap());
    let entry = |body: &str| Entry {
        stream: stream.into(),
        body: Some(body.into()),
        ..Entry::new(Kind::Note)
    };
    assert_eq!(
        &data.open_body(&store, &entry(&old)).await.unwrap().unwrap()[..],
        b"tenant body"
    );
    let held = data.list().unwrap();
    assert_eq!(
        (held.len(), held[0].subject.as_deref(), held[0].epochs.len()),
        (1, None, 2)
    );
    assert!(data.export(None, true).unwrap().contains("digest_key"));

    // Replace the blob's bytes: caught before decryption.
    let path = stream_dir.join(tenbri_crypt::blob_path(&old).unwrap());
    let mut bytes = fs::read(&path).unwrap();
    bytes[30] ^= 1;
    fs::write(&path, bytes).unwrap();
    assert!(matches!(
        data.open_body(&store, &entry(&old)).await,
        Err(Error::Tampered(_))
    ));
    fs::remove_file(&path).unwrap();
    assert!(matches!(
        data.open_body(&store, &entry(&old)).await,
        Err(Error::MissingBlob(_))
    ));
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn the_key_store_is_owner_only_and_apart_from_the_stream() {
    let root = tmp("perms");
    let (stream_dir, keys_dir) = (root.join("stream"), root.join("keys"));
    fs::create_dir_all(&stream_dir).unwrap();
    let stream = "tnb1:0123456789abcdef0123456789abcdef";
    assert!(KeyStore::open(&stream_dir.join("keys"), &stream_dir, stream).is_err());
    let ks = KeyStore::open(&keys_dir, &stream_dir, stream).unwrap();
    let data = DataKeys::open(&ks).unwrap();
    data.digest(Some("cust_1"), b"x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file = fs::read_dir(data.dir())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let e = data.digest(Some("cust_1"), b"x").unwrap_err();
        assert!(e.to_string().contains("owner-only"), "{e}");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(data.dir(), fs::Permissions::from_mode(0o755)).unwrap();
        let e = DataKeys::open(&ks).unwrap_err();
        assert!(e.to_string().contains("chmod 700"), "{e}");
    }
    fs::remove_dir_all(&root).unwrap();
}
