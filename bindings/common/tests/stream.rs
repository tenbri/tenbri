//! A stream through the shared binding layer: create, intent, outcome, idempotent retry, verify,
//! query, read-only open.

use serde_json::{Value, json};
use tenbri_bindings::{
    IDEMPOTENCY_CONFLICT, INVALID_REQUEST, NO_SESSION_KEY, NOT_FOUND, Options, Stream,
};

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("tenbri-bindings-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn j(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn write_verify_query() {
    let root = dir("rw");
    let (path, keys) = (root.join("audit/support"), root.join("keys"));
    let o = Options {
        keys: Some(keys.clone()),
        create: true,
        ..Options::default()
    };
    let s = Stream::open(path.to_str().unwrap(), o.clone())
        .await
        .unwrap();
    assert!(s.writable());
    let fp = s.fingerprint().unwrap().to_owned();

    let draft = json!({
        "principal": {"kind": "agent", "id": "support"},
        "action": {"type": "issue_refund", "target": "stripe:ch_1"},
        "inputs": [{"ref": "policy:refund", "version": "14", "digest": format!("hmac-sha256:{}", "ab".repeat(32))}],
    });
    let intent = j(&s.intent(draft.to_string().as_bytes()).await.unwrap());
    assert_eq!(intent["phase"], "intent");
    assert_eq!(intent["source"], "sdk");
    assert_eq!(intent["durability"], "local");
    let outcome = j(&s
        .outcome(intent.to_string().as_bytes(), "ok", b"{}")
        .await
        .unwrap());
    assert_eq!(outcome["intent"], intent["id"]);
    assert_eq!(outcome["action"], intent["action"]);

    // The same id again is the original entry; a different entry with it is a conflict.
    let mut again = draft.clone();
    again["id"] = intent["id"].clone();
    again["ts"] = intent["ts"].clone();
    let replayed = j(&s.intent(again.to_string().as_bytes()).await.unwrap());
    assert_eq!(replayed, intent);
    again["action"]["target"] = "stripe:ch_2".into();
    let e = s.intent(again.to_string().as_bytes()).await.unwrap_err();
    assert_eq!(e.code, IDEMPOTENCY_CONFLICT);
    let e = s.intent(br#"{"kind":"note"}"#).await.unwrap_err();
    assert_eq!(e.code, INVALID_REQUEST);

    let r = j(&s.verify(Some(&fp)).await.unwrap());
    assert_eq!(r["broken"], Value::Null);
    assert_eq!(r["pinned_key"], fp.as_str());
    assert_eq!(r["entries"], 4);
    assert_eq!(j(&s.verify(None).await.unwrap())["pinned_key"], Value::Null);

    let q = j(&s
        .query(br#"{"inputs":[["policy:refund","14"]],"principal":"agent:support"}"#)
        .await
        .unwrap());
    assert_eq!(q.as_array().unwrap().len(), 1);
    assert_eq!(q[0]["verification"], "unpinned");
    assert_eq!(q[0]["entry"], intent);
    let q = j(&s.query(br#"{"action":"issue_refund"}"#).await.unwrap());
    assert_eq!(q.as_array().unwrap().len(), 2);
    s.close().await;

    // Pinned, and from another process's point of view: no keys here, so read-only.
    let o = Options {
        keys: Some(root.join("elsewhere")),
        key: Some(fp.clone()),
        create: false,
        ..Options::default()
    };
    let r = Stream::open(&format!("file://{}", path.display()), o)
        .await
        .unwrap();
    assert!(!r.writable());
    assert!(
        !root.join("elsewhere").exists(),
        "a reader creates no key directory"
    );
    assert_eq!(
        r.append(b"{\"kind\":\"note\"}").await.unwrap_err().code,
        NO_SESSION_KEY
    );
    let q = j(&r.query(b"{\"limit\":1,\"after_seq\":2}").await.unwrap());
    assert_eq!(q[0]["verification"], "verified");
    assert_eq!(q[0]["entry"], intent);

    // Opening again with create keeps the stream.
    let s = Stream::open(
        path.to_str().unwrap(),
        Options {
            keys: Some(keys),
            create: true,
            ..Options::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(s.fingerprint(), Some(fp.as_str()));
    let e = Stream::open(root.join("nothing").to_str().unwrap(), Options::default())
        .await
        .err()
        .unwrap();
    assert_eq!(e.code, NOT_FOUND);
    let _ = std::fs::remove_dir_all(&root);
}
