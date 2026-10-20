//! Receipts over REST and gRPC, and checkpoints timestamped by an RFC 3161 authority.

use std::sync::Arc;

use serde_json::{Value, json};
use tenbri_anchor::test_tsa::TestTsa;
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_server::proto::tenbri_service_client::TenbriServiceClient;
use tenbri_server::{Config, Daemon, proto as pb};
use tenbri_store::LocalStore;
use tenbri_writer::{Writer, new_id, now_ms};

const TOKEN: &str = "tnbt_receipts";

#[tokio::test(flavor = "multi_thread")]
async fn receipts_and_timestamps() {
    let tsa = TestTsa::new(b"\x09 tenbrid");
    let roots = tenbri_anchor::parse_roots(tsa.root_pem().as_bytes()).unwrap();
    let tsa_url = tsa.serve().await.unwrap();

    let dir = std::env::temp_dir().join(format!("tenbrid-receipt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("audit/support");
    std::fs::create_dir_all(&path).unwrap();
    let stream_key = Key::new_stream().unwrap();
    let pin = stream_key.fingerprint();
    let id = tenbri_core::sign::stream_id(&stream_key.signing.verifying_key());
    let ks = KeyStore::open(&dir.join("keys"), &path, &id).unwrap();
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    ks.save(&stream_key, Backend::File).unwrap();
    ks.save(&session, Backend::File).unwrap();
    Writer::create(LocalStore::open(&path).unwrap(), &stream_key, session)
        .await
        .unwrap();

    let text = format!(
        "keys = \"keys\"\n[streams.support]\npath = \"audit/support\"\n[anchor]\ntsa = \"{tsa_url}\"\n\
         [[tokens]]\nsha256 = \"{}\"\nprincipal = {{ kind = \"agent\", id = \"a\" }}\n",
        tenbri_core::sign::sha256(TOKEN.as_bytes())
    );
    let config = Config::parse(&text, &dir, |_| None).unwrap();
    let daemon = Arc::new(Daemon::open(&config).await.unwrap());
    let rest = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (r, g) = (rest.local_addr().unwrap(), grpc.local_addr().unwrap());
    tokio::spawn(tenbri_server::serve(
        daemon.clone(),
        rest,
        grpc,
        std::future::pending(),
    ));
    let http = reqwest::Client::new();
    let get = |id: &str| {
        http.get(format!(
            "http://{r}/v1/streams/support/entries/{id}/receipt"
        ))
        .bearer_auth(TOKEN)
        .send()
    };

    let first = new_id(now_ms()).unwrap();
    let res = http
        .post(format!("http://{r}/v1/streams/support/intents"))
        .bearer_auth(TOKEN)
        .header("idempotency-key", &first)
        .json(&json!({"action": {"type": "reply_ticket", "target": "t:1"}}))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let res = get(&first).await.unwrap();
    assert_eq!(res.status().as_u16(), 503);
    let v: Value = res.json().await.unwrap();
    assert_eq!(v["error"]["code"], "TENBRI_NOT_CHECKPOINTED", "{v}");
    let v: Value = get("01ARZ3NDEKTSV4RRFFQ69G5FAV")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["error"]["code"], "TENBRI_NOT_FOUND", "{v}");

    // 1,000 more entries: the writer checkpoints.
    let notes: Vec<Value> = (0..1000)
        .map(|_| json!({"id": new_id(now_ms()).unwrap(), "kind": "note"}))
        .collect();
    let res = http
        .post(format!("http://{r}/v1/streams/support/entries"))
        .bearer_auth(TOKEN)
        .json(&json!({ "entries": notes }))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    let res = get(&first).await.unwrap();
    assert_eq!(res.status().as_u16(), 200);
    let receipt = res.bytes().await.unwrap();
    let v = tenbri_anchor::verify_receipt(&receipt, &pin, Some(&roots)).unwrap();
    assert_eq!(v.receipt.proved()[0].id, first);
    assert_eq!(v.timestamps.unwrap().len(), 0);

    // What [anchor] runs every hour: the latest checkpoint gets a token, once.
    let written = daemon.anchor(&tsa_url).await;
    assert_eq!(written, vec!["anchors/000000001003.tsr".to_owned()]);
    assert!(daemon.anchor(&tsa_url).await.is_empty());

    let ch = tonic::transport::Channel::from_shared(format!("http://{g}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut c = TenbriServiceClient::new(ch);
    let mut req = tonic::Request::new(pb::GetReceiptRequest {
        stream: "support".into(),
        id: first.clone(),
    });
    req.metadata_mut()
        .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
    let receipt = c.get_receipt(req).await.unwrap().into_inner().receipt;
    let v = tenbri_anchor::verify_receipt(&receipt, &pin, Some(&roots)).unwrap();
    assert_eq!(v.receipt.checkpoint.size, 1003);
    assert_eq!(v.timestamps.unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
