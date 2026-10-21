//! tenbrid with the stream key in a PKCS#11 token (SoftHSM in CI, when `TENBRI_TEST_PKCS11_MODULE`,
//! `TENBRI_TEST_PKCS11_TOKEN` and `TENBRI_TEST_PKCS11_PIN` are set): it refuses to start without
//! the token, and renews its session key through it.
#![cfg(feature = "pkcs11")]

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use tenbri_core::{KeyEvent, Kind, Role};
use tenbri_keys::pkcs11::Token;
use tenbri_keys::{Backend, Key, KeyStore};
use tenbri_server::{Config, Daemon};
use tenbri_store::LocalStore;
use tenbri_writer::{Reader, Writer, new_id, now_ms, verify};
use zeroize::Zeroizing;

const TOKEN: &str = "tnbt_pkcs11";

#[tokio::test(flavor = "multi_thread")]
async fn tenbrid_renews_its_session_key_through_the_token() {
    let var = |k: &str| std::env::var(format!("TENBRI_TEST_PKCS11_{k}")).ok();
    let (Some(module), Some(label), Some(pin)) = (var("MODULE"), var("TOKEN"), var("PIN")) else {
        eprintln!("TENBRI_TEST_PKCS11_* not set: no PKCS#11 token in this run");
        return;
    };
    let token = Token::new(
        PathBuf::from(&module),
        label.clone(),
        Zeroizing::new(pin.clone()),
    );

    // A stream whose key is in the token, with a session key that expires within tenbrid's
    // renewal margin: tenbrid must have the token certify a new one before it writes.
    let dir = std::env::temp_dir().join(format!("tenbrid-pkcs11-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("audit/support");
    std::fs::create_dir_all(&path).unwrap();
    let sk = token.new_stream().unwrap();
    let pin_fp = sk.fingerprint();
    let id = tenbri_core::sign::stream_id(&sk.verifying_key());
    let ks = KeyStore::open(&dir.join("keys"), &path, &id).unwrap();
    let dying = Key::new_session(now_ms(), 30_000).unwrap();
    ks.save(&sk, Backend::Pkcs11).unwrap();
    ks.save(&dying, Backend::File).unwrap();
    let store = LocalStore::open(&path).unwrap();
    Writer::create(store.clone(), &sk, dying.clone())
        .await
        .unwrap();

    let text = format!(
        "keys = \"keys\"\n[streams.support]\npath = \"audit/support\"\n\
         [[tokens]]\nsha256 = \"{}\"\nprincipal = {{ kind = \"agent\", id = \"a\" }}\n",
        tenbri_core::sign::sha256(TOKEN.as_bytes())
    );
    let env = |k: &str| match k {
        "TENBRI_PKCS11_MODULE" => Some(module.clone()),
        "TENBRI_PKCS11_TOKEN" => Some(label.clone()),
        "TENBRI_PKCS11_PIN" => Some(pin.clone()),
        _ => None,
    };

    // Without the token configured, tenbrid does not start.
    let config = Config::parse(&text, &dir, |_| None).unwrap();
    let err = Daemon::open(&config).await.err().unwrap();
    assert!(err.contains("configure [pkcs11]"), "{err}");

    let config = Config::parse(&text, &dir, env).unwrap();
    let daemon = Arc::new(Daemon::open(&config).await.unwrap());
    let rest = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let r = rest.local_addr().unwrap();
    tokio::spawn(tenbri_server::serve(
        daemon,
        rest,
        grpc,
        std::future::pending(),
    ));
    let res = reqwest::Client::new()
        .post(format!("http://{r}/v1/streams/support/intents"))
        .bearer_auth(TOKEN)
        .header("idempotency-key", new_id(now_ms()).unwrap())
        .json(&json!({"action": {"type": "reply_ticket", "target": "t:1"}}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success(), "{res:?}");

    // The stream: genesis, the dying session, a session certified by the token, the intent
    // signed by that session; and it verifies.
    let entries = Reader::new(&store, Some(&pin_fp)).poll().await.unwrap();
    let renewed = entries
        .iter()
        .find_map(|e| match &e.key {
            Some(KeyEvent::Certify {
                id,
                role: Role::Session,
                ..
            }) if *id != dying.id => Some((e.signer.clone(), id.clone())),
            _ => None,
        })
        .expect("a session certified by tenbrid");
    assert_eq!(renewed.0, sk.id, "certified by the stream key in the token");
    let last = entries.last().unwrap();
    assert_eq!(
        (last.kind, last.signer.as_str()),
        (Kind::Decision, renewed.1.as_str())
    );
    let report = verify(&store, Some(&pin_fp)).await.unwrap();
    assert_eq!(
        (report.broken, report.entries),
        (None, entries.len() as u64)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
