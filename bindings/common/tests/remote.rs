//! A stream written through tenbrid: the writing process holds a token, never a key.

use std::sync::Arc;

use serde_json::Value;
use tenbri_bindings::{FORBIDDEN, Options, Stream, UNAUTHENTICATED};
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_server::{Config, Daemon};
use tenbri_store::LocalStore;
use tenbri_writer::{Writer, now_ms};

const TOKEN: &str = "tnbt_agent_support";

fn j(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

#[tokio::test]
async fn writes_through_tenbrid_without_keys() {
    let dir = std::env::temp_dir().join(format!("tenbri-remote-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("audit");
    std::fs::create_dir_all(&path).unwrap();
    let stream_key = Key::new_stream().unwrap();
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    let id = tenbri_core::sign::stream_id(&stream_key.signing.verifying_key());
    let ks = KeyStore::open(&dir.join("keys"), &path, &id).unwrap();
    ks.save(&stream_key, Backend::File).unwrap();
    ks.save(&session, Backend::File).unwrap();
    Writer::create(LocalStore::open(&path).unwrap(), &stream_key, session)
        .await
        .unwrap();
    let config = format!(
        "keys = \"keys\"\nindex_dir = \"index\"\n[streams.support]\npath = \"audit\"\n\
         [[tokens]]\nsha256 = \"{}\"\nprincipal = {{ kind = \"agent\", id = \"support\" }}\n",
        tenbri_core::sign::sha256(TOKEN.as_bytes())
    );
    let daemon = Arc::new(
        Daemon::open(&Config::parse(&config, &dir, |_| None).unwrap())
            .await
            .unwrap(),
    );
    let rest = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/support", rest.local_addr().unwrap());
    tokio::spawn(tenbri_server::serve(
        daemon,
        rest,
        grpc,
        std::future::pending(),
    ));
    let opts = |t: &str| Options {
        token: Some(t.into()),
        ..Options::default()
    };

    let e = Stream::open(&url, opts("tnbt_wrong")).await.err().unwrap();
    assert_eq!(e.code, UNAUTHENTICATED);

    let s = Stream::open(&url, opts(TOKEN)).await.unwrap();
    assert_eq!(s.id(), id);
    assert!(s.writable());
    let draft = br#"{"action":{"type":"reply_ticket","target":"zendesk:ticket/1"}}"#;
    let intent = j(&s.intent(draft).await.unwrap());
    // tenbrid signed it with its session key and bound the token's principal.
    assert_eq!(intent["principal"]["id"], "support");
    assert_eq!(intent["source"], "sdk");
    let mut again = j(std::str::from_utf8(draft).unwrap());
    again["id"] = intent["id"].clone();
    assert_eq!(
        j(&s.intent(again.to_string().as_bytes()).await.unwrap()),
        intent,
        "a retry replays"
    );
    let outcome = j(&s
        .outcome(intent.to_string().as_bytes(), "ok", b"{}")
        .await
        .unwrap());
    assert_eq!(outcome["intent"], intent["id"]);

    // Naming someone else is refused: the token, not the agent, says who acted.
    let e = s
        .append(br#"{"kind":"decision","phase":"intent","principal":{"kind":"agent","id":"x"},"action":{"type":"a"}}"#)
        .await
        .err()
        .unwrap();
    assert_eq!(e.code, FORBIDDEN);
    assert!(e.id.is_some(), "the id to retry with");

    let q = j(&s
        .query(br#"{"action":"reply_ticket","limit":5}"#)
        .await
        .unwrap());
    assert_eq!(q.as_array().unwrap().len(), 2);
    assert_eq!(q[0]["entry"], intent);
    let v = j(&s.verify(None).await.unwrap());
    assert_eq!(
        (v["entries"].as_u64(), &v["broken"]),
        (Some(4), &Value::Null),
        "two key entries, intent, outcome"
    );
    assert_eq!(v["pinned_key"], stream_key.fingerprint());
    // tenbrid keys the digest with its data key, as the agent would with the keys in hand.
    let data = tenbri_crypt::DataKeys::open(&ks).unwrap();
    assert_eq!(
        s.digest(Some("cust_42"), b"x").await.unwrap(),
        data.digest(Some("cust_42"), b"x").unwrap()
    );
    assert_eq!(
        s.digest(None, b"x").await.unwrap(),
        data.digest(None, b"x").unwrap()
    );
    let e = s.digest(Some(""), b"x").await.err().unwrap();
    assert_eq!(e.code, tenbri_bindings::INVALID_REQUEST);
}
