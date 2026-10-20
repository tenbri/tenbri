//! tenbrid over the network, REST and gRPC: appends, idempotency, every error code a client can
//! cause, schemas, query, tail, verify, restart and graceful shutdown.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_server::proto::tenbri_service_client::TenbriServiceClient;
use tenbri_server::proto::{self as pb};
use tenbri_server::{Config, Daemon};
use tenbri_store::LocalStore;
use tenbri_writer::{Writer, new_id, now_ms};
use tokio::sync::oneshot;
use tonic::transport::Channel;

const AGENT: &str = "tnbt_agent_a";
const ALICE: &str = "tnbt_person_alice";
const OTHER: &str = "tnbt_agent_c_other_only";

const SCHEMA: &str = r#"
[actions.reply_ticket]
target = "zendesk:ticket/*"

[actions.issue_refund]
inputs = ["policy:refund"]
rule = true
approval = true

[actions.issue_refund.fields."rule.result"]
allowed = ["allow"]
"#;

struct Server {
    dir: PathBuf,
    rest: String,
    grpc: String,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tenbrid-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Creates a stream with its keys, as `tenbri init` does.
async fn init(dir: &Path, name: &str) {
    let path = dir.join("audit").join(name);
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
}

fn hash(token: &str) -> String {
    tenbri_core::sign::sha256(token.as_bytes())
}

async fn start(dir: &Path, extra: &str) -> Server {
    std::fs::write(dir.join("tenbri.toml"), SCHEMA).unwrap();
    let text = format!(
        r#"
keys = "keys"
schema = "tenbri.toml"
index_dir = "index"
{extra}
[streams.support]
path = "audit/support"
[streams.other]
path = "audit/other"

[[tokens]]
sha256 = "{}"
principal = {{ kind = "agent", id = "a" }}

[[tokens]]
sha256 = "{}"
principal = {{ kind = "person", id = "alice" }}

[[tokens]]
sha256 = "{}"
principal = {{ kind = "agent", id = "c" }}
streams = ["other"]
"#,
        hash(AGENT),
        hash(ALICE),
        hash(OTHER)
    );
    let config = Config::parse(&text, dir, |_| None).unwrap();
    let daemon = Arc::new(Daemon::open(&config).await.unwrap());
    let rest = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (r, g) = (rest.local_addr().unwrap(), grpc.local_addr().unwrap());
    let (stop, rx) = oneshot::channel();
    let task = tokio::spawn(tenbri_server::serve(daemon, rest, grpc, async move {
        let _ = rx.await;
    }));
    Server {
        dir: dir.to_owned(),
        rest: format!("http://{r}"),
        grpc: format!("http://{g}"),
        stop: Some(stop),
        task,
    }
}

impl Server {
    async fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .expect("shutdown finishes")
            .unwrap()
            .unwrap();
    }

    async fn grpc(&self) -> TenbriServiceClient<Channel> {
        let ch = Channel::from_shared(self.grpc.clone())
            .unwrap()
            .connect()
            .await
            .unwrap();
        TenbriServiceClient::new(ch)
    }
}

fn id() -> String {
    new_id(now_ms()).unwrap()
}

/// POSTs `body` and returns the status and JSON body.
async fn post(
    s: &Server,
    path: &str,
    token: Option<&str>,
    key: Option<&str>,
    body: &str,
) -> (StatusCode, Value) {
    let mut r = reqwest::Client::new()
        .post(format!("{}{path}", s.rest))
        .header("content-type", "application/json")
        .body(body.to_owned());
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    if let Some(k) = key {
        r = r.header("idempotency-key", k);
    }
    let res = r.send().await.unwrap();
    let status = res.status();
    (status, res.json().await.unwrap())
}

async fn get(s: &Server, path: &str, token: Option<&str>) -> (StatusCode, Value) {
    let mut r = reqwest::Client::new().get(format!("{}{path}", s.rest));
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    let res = r.send().await.unwrap();
    let status = res.status();
    (status, res.json().await.unwrap())
}

async fn q(s: &Server, query: &str) -> Value {
    let (st, v) = get(
        s,
        &format!("/v1/streams/support/entries?{query}"),
        Some(AGENT),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{query}: {v}");
    v
}

fn stream_id_of(entry_json: &str) -> String {
    serde_json::from_str::<Value>(entry_json).unwrap()["stream"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn code(v: &Value) -> &str {
    v["error"]["code"].as_str().unwrap_or_default()
}

fn intent(target: &str) -> String {
    json!({
        "action": {"type": "reply_ticket", "target": target},
        "inputs": [{"ref": "policy:refund", "version": "14", "digest": "hmac-sha256:9f2c41aa9f2c41aa9f2c41aa9f2c41aa9f2c41aa9f2c41aa9f2c41aa9f2c41aa"}],
        "subject": "subj:42",
    })
    .to_string()
}

async fn entries(s: &Server) -> u64 {
    let (_, v) = get(s, "/v1/streams/support/verify", Some(AGENT)).await;
    assert!(v.get("broken").is_none(), "{v}");
    v["entries"].as_u64().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_round_trip() {
    let dir = tmp("rest");
    init(&dir, "support").await;
    init(&dir, "other").await;
    let s = start(&dir, "").await;
    let intents = "/v1/streams/support/intents";

    let (st, v) = get(&s, "/v1/ready", None).await;
    assert_eq!((st, v["status"].as_str()), (StatusCode::OK, Some("ready")));
    assert_eq!(get(&s, "/v1/health", None).await.0, StatusCode::OK);

    // An intent: kind, phase, principal, source and durability are filled in.
    let k = id();
    let body = intent("zendesk:ticket/4821");
    let (st, v) = post(&s, intents, Some(AGENT), Some(&k), &body).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    let e = &v["entry"];
    assert_eq!(e["id"], k.as_str());
    assert_eq!(e["kind"], "decision");
    assert_eq!(e["phase"], "intent");
    assert_eq!(e["principal"], json!({"kind": "agent", "id": "a"}));
    assert_eq!(
        (e["source"].as_str(), e["durability"].as_str()),
        (Some("sdk"), Some("local"))
    );
    assert_eq!(v["replayed"], false);
    let seq = e["seq"].as_u64().unwrap();

    // The same key and draft: the original entry. Another draft: a conflict.
    let (st, again) = post(&s, intents, Some(AGENT), Some(&k), &body).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!((&again["entry"], &again["replayed"]), (e, &json!(true)));
    let (st, v) = post(
        &s,
        intents,
        Some(AGENT),
        Some(&k),
        &intent("zendesk:ticket/1"),
    )
    .await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::CONFLICT, "TENBRI_IDEMPOTENCY_CONFLICT")
    );

    // An outcome takes the intent's principal, action and subject.
    let (st, v) = post(
        &s,
        "/v1/streams/support/outcomes",
        Some(AGENT),
        Some(&id()),
        &json!({"intent": k, "status": "ok"}).to_string(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert_eq!(v["entry"]["action"], e["action"]);
    assert_eq!(v["entry"]["subject"], "subj:42");

    // A refund needs an approval: alice approves with her own token, then the agent acts.
    let (st, approval) = post(
        &s,
        "/v1/streams/support/approvals",
        Some(ALICE),
        Some(&id()),
        &json!({"action": {"type": "issue_refund", "target": "stripe:charge/ch_1"}}).to_string(),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{approval}");
    let line = serde_json::to_string(&approval["entry"]).unwrap();
    let approval_hash = tenbri_core::sign::entry_hash(line.as_bytes());
    let refund = json!({
        "action": {"type": "issue_refund", "target": "stripe:charge/ch_1"},
        "inputs": [{"ref": "policy:refund", "version": "14", "digest": format!("hmac-sha256:{}", "00".repeat(32))}],
        "rule": {"ref": "refund-limit", "version": "3", "result": "allow"},
        "approval": {"by": {"kind": "person", "id": "alice"}, "entry": approval_hash},
    });
    let (st, v) = post(&s, intents, Some(AGENT), Some(&id()), &refund.to_string()).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");

    // A batch: an intent and its outcome, in order.
    let (b1, b2) = (id(), id());
    let batch = json!({"entries": [
        {"id": b1, "kind": "decision", "phase": "intent", "action": {"type": "reply_ticket", "target": "zendesk:ticket/7"}},
        {"id": b2, "kind": "decision", "phase": "outcome", "intent": b1, "status": "error"},
    ]})
    .to_string();
    let (st, v) = post(&s, "/v1/streams/support/entries", Some(AGENT), None, &batch).await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let out = v["entries"].as_array().unwrap();
    assert_eq!(out[1]["entry"]["intent"], b1.as_str());
    assert_eq!(
        out[1]["entry"]["seq"],
        out[0]["entry"]["seq"].as_u64().unwrap() + 1
    );
    // Retried as a whole: every entry replayed, nothing written twice.
    let n = entries(&s).await;
    let (_, v) = post(&s, "/v1/streams/support/entries", Some(AGENT), None, &batch).await;
    assert!(
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["replayed"] == true)
    );
    assert_eq!(entries(&s).await, n);

    // Reads, by name or by stream id.
    let (st, v) = get(&s, &format!("/v1/streams/support/entries/{k}"), Some(AGENT)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        (&v["entry"], v["verification"].as_str()),
        (e, Some("verified"))
    );
    let stream_id = e["stream"].as_str().unwrap();
    let (st, _) = get(
        &s,
        &format!("/v1/streams/{stream_id}/entries/{k}"),
        Some(AGENT),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let seqs = |v: &Value| -> Vec<u64> {
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["entry"]["seq"].as_u64().unwrap())
            .collect()
    };
    assert_eq!(
        seqs(&q(&s, "input=policy:refund@14&action=reply_ticket").await),
        [seq]
    );
    assert_eq!(seqs(&q(&s, "input=policy:refund@14").await).len(), 2);
    assert_eq!(seqs(&q(&s, "subject=subj:42").await), [seq, seq + 1]);
    assert_eq!(seqs(&q(&s, "principal=person:alice").await).len(), 1);
    assert_eq!(seqs(&q(&s, "target=zendesk:ticket/7").await).len(), 2);
    let page = q(&s, "action=reply_ticket&limit=2").await;
    assert_eq!(seqs(&page).len(), 2);
    let next = page["next_after_seq"].as_u64().unwrap();
    let rest = q(&s, &format!("action=reply_ticket&after_seq={next}")).await;
    assert_eq!(seqs(&rest).len(), 2);
    assert!(rest.get("next_after_seq").is_none());
    assert_eq!(seqs(&q(&s, "rule=refund-limit@3").await).len(), 1);
    assert_eq!(seqs(&q(&s, "rule=refund-limit").await).len(), 1);
    assert_eq!(seqs(&q(&s, "input=policy:refund").await).len(), 2);
    assert_eq!(seqs(&q(&s, "status=error").await).len(), 1);
    assert_eq!(seqs(&q(&s, "status=ok&subject=subj:42").await), [seq + 1]);
    assert_eq!(
        seqs(&q(&s, "trace_id=0af7651916cd43dd8448eb211c80319c").await).len(),
        0
    );
    let all = q(&s, "since=1h&limit=1000").await;
    assert_eq!(seqs(&q(&s, "until=1h").await).len(), 0);
    assert_eq!(seqs(&all).len() as u64, entries(&s).await);
    // Every result carries its seq and entry hash; the page, what the index is current to.
    let first = &all["entries"][0];
    let line = serde_json::to_string(&first["entry"]).unwrap();
    assert_eq!(first["seq"], first["entry"]["seq"]);
    assert_eq!(
        first["hash"].as_str().unwrap(),
        tenbri_core::sign::entry_hash(line.as_bytes())
    );
    assert_eq!(all["as_of"]["stream"], e["stream"]);
    assert_eq!(all["as_of"]["seq"].as_u64().unwrap(), entries(&s).await);
    let (st, v) = get(
        &s,
        "/v1/streams/support/entries?since=yesterday",
        Some(AGENT),
    )
    .await;
    assert_eq!(
        (st, code(&v)),
        (StatusCode::BAD_REQUEST, "TENBRI_INVALID_REQUEST")
    );

    let (st, v) = get(&s, "/v1/schemas", Some(AGENT)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["actions"]["issue_refund"]["approval"], true);

    let (st, v) = get(&s, "/v1/streams/support/verify", Some(AGENT)).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(v["stream"], stream_id);
    assert!(v["pinned_key"].as_str().unwrap().starts_with("sha256:"));
    assert!(v.get("broken").is_none());

    // Restarted, tenbrid still knows every key it acknowledged.
    s.stop().await;
    // A query index that claims to be current but holds other entries is noticed and rebuilt.
    let ixdir = tenbri_index::dir_for(&dir.join("index"), stream_id);
    {
        let mut ix = tenbri_index::find(&ixdir).unwrap().unwrap();
        let st = ix.state().unwrap().unwrap();
        ix.clear().unwrap();
        let bogus = tenbri_index::Row {
            seq: 1,
            hash: "sha256:bogus".into(),
            action: Some("reply_ticket".into()),
            line: "{}".into(),
            ..Default::default()
        };
        ix.append(&[bogus], &st).unwrap();
    }
    let s = start(&dir, "").await;
    let (st, v) = post(&s, intents, Some(AGENT), Some(&k), &body).await;
    assert_eq!((st, &v["entry"]), (StatusCode::OK, e));
    assert_eq!(seqs(&q(&s, "subject=subj:42").await), [seq, seq + 1]);
    s.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_errors_write_nothing() {
    let dir = tmp("errors");
    init(&dir, "support").await;
    init(&dir, "other").await;
    let s = start(&dir, "").await;
    let intents = "/v1/streams/support/intents";
    let before = entries(&s).await;
    let ok = intent("zendesk:ticket/1");

    for (token, key, path, body, status, want) in [
        (None, Some(id()), intents, ok.clone(), 401, "TENBRI_UNAUTHENTICATED"),
        (Some("nope"), Some(id()), intents, ok.clone(), 401, "TENBRI_UNAUTHENTICATED"),
        (Some(OTHER), Some(id()), intents, ok.clone(), 403, "TENBRI_FORBIDDEN"),
        (Some(AGENT), Some(id()), "/v1/streams/nope/intents", ok.clone(), 404, "TENBRI_NOT_FOUND"),
        (Some(AGENT), None, intents, ok.clone(), 400, "TENBRI_INVALID_REQUEST"),
        (Some(AGENT), Some("not-a-ulid".into()), intents, ok.clone(), 400, "TENBRI_INVALID_REQUEST"),
        (Some(AGENT), Some(id()), intents, "[1]".into(), 400, "TENBRI_INVALID_REQUEST"),
        (Some(AGENT), Some(id()), intents, "{".into(), 400, "TENBRI_INVALID_ENTRY"),
        (Some(AGENT), Some(id()), intents, r#"{"kind":"note"}"#.into(), 400, "TENBRI_INVALID_REQUEST"),
        (Some(AGENT), Some(id()), intents, r#"{"seq":3}"#.into(), 400, "TENBRI_INVALID_ENTRY"),
        (Some(AGENT), Some(id()), intents, r#"{"action":{"type":"reply_ticket"},"x":1}"#.into(), 400, "TENBRI_INVALID_ENTRY"),
        (Some(AGENT), Some(id()), intents, r#"{"durability":"replicated","action":{"type":"reply_ticket","target":"zendesk:ticket/1"}}"#.into(), 400, "TENBRI_INVALID_ENTRY"),
        (Some(AGENT), Some(id()), intents, r#"{"principal":{"kind":"agent","id":"b"},"action":{"type":"reply_ticket","target":"zendesk:ticket/1"}}"#.into(), 403, "TENBRI_FORBIDDEN"),
        (Some(AGENT), Some(id()), intents, r#"{"action":{"type":"reply_ticket","target":"jira:1"}}"#.into(), 422, "TENBRI_SCHEMA_VIOLATION"),
        (Some(AGENT), Some(id()), intents, r#"{"action":{"type":"delete_database"}}"#.into(), 422, "TENBRI_SCHEMA_VIOLATION"),
        (Some(AGENT), Some(id()), "/v1/streams/support/outcomes", format!(r#"{{"intent":"{}","status":"ok"}}"#, id()), 400, "TENBRI_INVALID_ENTRY"),
        (Some(AGENT), Some(id()), "/v1/streams/support/entries", r#"{"entries":[]}"#.into(), 400, "TENBRI_INVALID_REQUEST"),
    ] {
        let (st, v) = post(&s, path, token, key.as_deref(), &body).await;
        assert_eq!((st.as_u16(), code(&v)), (status, want), "{body}: {v}");
    }

    // Duplicate keys are refused, with the format's own code as the reason.
    let (_, v) = post(
        &s,
        intents,
        Some(AGENT),
        Some(&id()),
        r#"{"subject":"a","subject":"b"}"#,
    )
    .await;
    assert_eq!(v["error"]["reason"], "duplicate_key");
    let (_, v) = post(
        &s,
        intents,
        Some(AGENT),
        Some(&id()),
        r#"{"action":{"type":"reply_ticket"},"x":1}"#,
    )
    .await;
    assert_eq!(v["error"]["reason"], "unknown_field");
    // Schema violations say where.
    let (_, v) = post(
        &s,
        intents,
        Some(AGENT),
        Some(&id()),
        r#"{"action":{"type":"issue_refund"},"rule":{"ref":"r","version":"1","result":"deny"}}"#,
    )
    .await;
    let paths: Vec<&str> = v["error"]["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["inputs", "approval", "rule.result"]);

    // A batch is checked whole: one bad entry, nothing written.
    let batch = json!({"entries": [
        {"id": id(), "kind": "decision", "phase": "intent", "action": {"type": "reply_ticket", "target": "zendesk:ticket/1"}},
        {"id": id(), "kind": "decision", "phase": "intent", "action": {"type": "nope"}},
    ]});
    let (st, v) = post(
        &s,
        "/v1/streams/support/entries",
        Some(AGENT),
        None,
        &batch.to_string(),
    )
    .await;
    assert_eq!((st.as_u16(), code(&v)), (422, "TENBRI_SCHEMA_VIOLATION"));
    let same = id();
    let batch = json!({"entries": [
        {"id": same, "kind": "decision", "phase": "intent", "action": {"type": "reply_ticket", "target": "zendesk:ticket/1"}},
        {"id": same, "kind": "decision", "phase": "intent", "action": {"type": "reply_ticket", "target": "zendesk:ticket/1"}},
    ]});
    let (st, v) = post(
        &s,
        "/v1/streams/support/entries",
        Some(AGENT),
        None,
        &batch.to_string(),
    )
    .await;
    assert_eq!((st.as_u16(), code(&v)), (400, "TENBRI_INVALID_REQUEST"));
    let batch = json!({"entries": [{"kind": "decision", "phase": "intent", "action": {"type": "reply_ticket", "target": "zendesk:ticket/1"}}]});
    let (st, _) = post(
        &s,
        "/v1/streams/support/entries",
        Some(AGENT),
        None,
        &batch.to_string(),
    )
    .await;
    assert_eq!(st.as_u16(), 400, "a batch entry needs its id");

    let (st, v) = get(
        &s,
        &format!("/v1/streams/support/entries/{}", id()),
        Some(AGENT),
    )
    .await;
    assert_eq!((st.as_u16(), code(&v)), (404, "TENBRI_NOT_FOUND"));
    let (st, v) = get(&s, "/v1/streams/support/entries?actoin=x", Some(AGENT)).await;
    assert_eq!((st.as_u16(), code(&v)), (400, "TENBRI_INVALID_REQUEST"));
    let (st, _) = get(&s, "/v1/schemas", None).await;
    assert_eq!(st.as_u16(), 401);

    assert_eq!(entries(&s).await, before, "no error wrote anything");
    s.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Reads server-sent events until `n` entry events arrived; returns their sequence numbers.
async fn sse_entries<B: AsRef<[u8]>>(
    body: &mut (impl futures_util::Stream<Item = reqwest::Result<B>> + Unpin),
    buf: &mut String,
    n: usize,
) -> Vec<u64> {
    let mut seqs = vec![];
    while seqs.len() < n {
        while let Some(i) = buf.find("\n\n") {
            let event: String = buf.drain(..i + 2).collect();
            if event.contains("event: entry") {
                let data = event
                    .lines()
                    .find_map(|l| l.strip_prefix("data: "))
                    .unwrap();
                let v: Value = serde_json::from_str(data).unwrap();
                assert_eq!(v["verification"], "verified");
                seqs.push(v["entry"]["seq"].as_u64().unwrap());
            }
        }
        if seqs.len() >= n {
            break;
        }
        let chunk = tokio::time::timeout(Duration::from_secs(10), body.next())
            .await
            .expect("an event in time")
            .expect("the stream is open")
            .unwrap();
        buf.push_str(std::str::from_utf8(chunk.as_ref()).unwrap());
    }
    seqs
}

#[tokio::test(flavor = "multi_thread")]
async fn rest_tail_then_graceful_shutdown() {
    let dir = tmp("tail");
    init(&dir, "support").await;
    init(&dir, "other").await;
    let s = start(&dir, "").await;
    let res = reqwest::Client::new()
        .get(format!("{}/v1/streams/support/tail?after_seq=1", s.rest))
        .bearer_auth(AGENT)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let mut body = res.bytes_stream();
    let mut buf = String::new();
    // The backlog after seq 1: the session key's certificate.
    assert_eq!(sse_entries(&mut body, &mut buf, 1).await, [2]);
    let (st, v) = post(
        &s,
        "/v1/streams/support/intents",
        Some(AGENT),
        Some(&id()),
        &intent("zendesk:ticket/9"),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert_eq!(sse_entries(&mut body, &mut buf, 1).await, [3]);

    // Shutdown ends the tail and returns; what was acknowledged is on disk and verifies.
    let dir = s.dir.clone();
    s.stop().await;
    let rest = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(c) = body.next().await {
            if c.is_err() {
                break;
            }
        }
    })
    .await;
    assert!(rest.is_ok(), "the tail ended");
    let r = tenbri_writer::verify(&LocalStore::open(dir.join("audit/support")).unwrap(), None)
        .await
        .unwrap();
    assert_eq!((r.entries, r.broken), (3, None));
    std::fs::remove_dir_all(&dir).unwrap();
}

fn authed<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut r = tonic::Request::new(msg);
    r.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    r
}

fn tenbri_code(s: &tonic::Status) -> &str {
    s.metadata()
        .get("tenbri-error-code")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_round_trip() {
    let dir = tmp("grpc");
    init(&dir, "support").await;
    init(&dir, "other").await;
    let s = start(&dir, "").await;
    let mut c = s.grpc().await;
    let stream = "support".to_owned();

    let mut tail = c
        .tail_entries(authed(
            AGENT,
            pb::TailEntriesRequest {
                stream: stream.clone(),
                after_seq: 2,
            },
        ))
        .await
        .unwrap()
        .into_inner();

    let k = id();
    let req = |key: &str, draft: String| pb::AppendIntentRequest {
        stream: stream.clone(),
        idempotency_key: key.to_owned(),
        draft_json: draft,
    };
    let a = c
        .append_intent(authed(AGENT, req(&k, intent("zendesk:ticket/1"))))
        .await
        .unwrap()
        .into_inner()
        .appended
        .unwrap();
    assert!(!a.replayed);
    let e: Value = serde_json::from_str(&a.entry_json).unwrap();
    assert_eq!(e["id"], k.as_str());
    // The canonical line, byte for byte: a client can hash it.
    assert_eq!(a.entry_json, serde_json::to_string(&e).unwrap());

    let again = c
        .append_intent(authed(AGENT, req(&k, intent("zendesk:ticket/1"))))
        .await
        .unwrap()
        .into_inner()
        .appended
        .unwrap();
    assert!(again.replayed);
    assert_eq!(again.entry_json, a.entry_json);
    let err = c
        .append_intent(authed(AGENT, req(&k, intent("zendesk:ticket/2"))))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::AlreadyExists);
    assert_eq!(tenbri_code(&err), "TENBRI_IDEMPOTENCY_CONFLICT");

    let err = c
        .append_intent(authed(
            AGENT,
            req(
                &id(),
                r#"{"action":{"type":"reply_ticket","target":"jira:1"}}"#.into(),
            ),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert_eq!(tenbri_code(&err), "TENBRI_SCHEMA_VIOLATION");
    let body: Value = serde_json::from_slice(
        &err.metadata()
            .get_bin("tenbri-error-bin")
            .unwrap()
            .to_bytes()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"]["violations"][0]["path"], "action.target");

    let err = c
        .append_intent(tonic::Request::new(req(&id(), intent("zendesk:ticket/1"))))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), tenbri_code(&err)),
        (tonic::Code::Unauthenticated, "TENBRI_UNAUTHENTICATED")
    );
    let err = c
        .append_intent(authed(AGENT, req("", intent("zendesk:ticket/1"))))
        .await
        .unwrap_err();
    assert_eq!(tenbri_code(&err), "TENBRI_INVALID_REQUEST");

    let o = c
        .append_outcome(authed(
            AGENT,
            pb::AppendOutcomeRequest {
                stream: stream.clone(),
                idempotency_key: id(),
                draft_json: json!({"intent": k, "status": "refused"}).to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .appended
        .unwrap();
    let o: Value = serde_json::from_str(&o.entry_json).unwrap();
    assert_eq!(
        (o["status"].as_str(), &o["action"]),
        (Some("refused"), &e["action"])
    );

    let ap = c
        .append_approval(authed(
            ALICE,
            pb::AppendApprovalRequest {
                stream: stream.clone(),
                idempotency_key: id(),
                draft_json: json!({"action": {"type": "issue_refund"}}).to_string(),
            },
        ))
        .await
        .unwrap();
    assert!(!ap.into_inner().appended.unwrap().replayed);

    let b = c
        .append_batch(authed(
            AGENT,
            pb::AppendBatchRequest {
                stream: stream.clone(),
                drafts_json: vec![
                    json!({"id": id(), "kind": "note", "action": {"type": "reply_ticket"}}).to_string(),
                    json!({"id": id(), "kind": "decision", "phase": "intent", "action": {"type": "reply_ticket", "target": "zendesk:ticket/3"}}).to_string(),
                ],
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(b.appended.len(), 2);

    let got = c
        .get_entry(authed(
            AGENT,
            pb::GetEntryRequest {
                stream: stream.clone(),
                id: k.clone(),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .entry
        .unwrap();
    assert_eq!(got.entry_json, a.entry_json);
    assert_eq!(got.verification, pb::Verification::Verified as i32);
    let err = c
        .get_entry(authed(
            AGENT,
            pb::GetEntryRequest {
                stream: stream.clone(),
                id: id(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), tenbri_code(&err)),
        (tonic::Code::NotFound, "TENBRI_NOT_FOUND")
    );

    let q = c
        .query_entries(authed(
            AGENT,
            pb::QueryEntriesRequest {
                stream: stream.clone(),
                inputs: vec!["policy:refund@14".into()],
                action: "reply_ticket".into(),
                ..Default::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(q.entries.len(), 1);
    assert_eq!(q.next_after_seq, 0);
    let (found, as_of) = (&q.entries[0], q.as_of.unwrap());
    assert_eq!(
        found.hash,
        tenbri_core::sign::entry_hash(found.entry_json.as_bytes())
    );
    assert!(found.seq > 0 && found.seq <= as_of.seq);
    assert_eq!(as_of.stream_id, stream_id_of(&found.entry_json));
    let q = c
        .query_entries(authed(
            AGENT,
            pb::QueryEntriesRequest {
                stream: stream.clone(),
                rule: "no-such-rule".into(),
                since: "7d".into(),
                ..Default::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(q.entries.is_empty());
    let err = c
        .query_entries(authed(
            AGENT,
            pb::QueryEntriesRequest {
                stream: stream.clone(),
                until: "soon".into(),
                ..Default::default()
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(tenbri_code(&err), "TENBRI_INVALID_REQUEST");
    let q = c
        .query_entries(authed(
            AGENT,
            pb::QueryEntriesRequest {
                stream: stream.clone(),
                limit: 2,
                ..Default::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((q.entries.len(), q.next_after_seq), (2, 2));

    // The tail saw everything written after seq 2, in order.
    let mut seqs = vec![];
    while seqs.len() < 5 {
        let t = tokio::time::timeout(Duration::from_secs(10), tail.message())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let e: Value = serde_json::from_str(&t.entry.unwrap().entry_json).unwrap();
        seqs.push(e["seq"].as_u64().unwrap());
    }
    assert_eq!(seqs, [3, 4, 5, 6, 7]);

    let v = c
        .verify_stream(authed(
            AGENT,
            pb::VerifyStreamRequest {
                stream: stream.clone(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!((v.entries, v.broken), (7, None));
    assert_eq!(v.stream_id, e["stream"].as_str().unwrap());

    let sch = c
        .list_schemas(authed(AGENT, pb::ListSchemasRequest {}))
        .await
        .unwrap()
        .into_inner();
    let sch: Value = serde_json::from_str(&sch.schemas_json).unwrap();
    assert_eq!(sch["unknown_actions"], "reject");

    let err = c
        .verify_stream(authed(
            OTHER,
            pb::VerifyStreamRequest {
                stream: stream.clone(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(
        (err.code(), tenbri_code(&err)),
        (tonic::Code::PermissionDenied, "TENBRI_FORBIDDEN")
    );

    // Shutdown ends the tail.
    s.stop().await;
    let end = tokio::time::timeout(Duration::from_secs(10), tail.message())
        .await
        .unwrap();
    assert!(!matches!(end, Ok(Some(_))));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A `traceparent` on an append becomes the entry's `trace` and comes back out through the query;
/// a retry under a new span replays; a draft's own `trace` wins; an invalid header is ignored.
#[tokio::test(flavor = "multi_thread")]
async fn traceparent_round_trip() {
    let dir = tmp("trace");
    init(&dir, "support").await;
    init(&dir, "other").await;
    let s = start(&dir, "").await;
    let (trace, span) = ("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7");
    let post_traced = |key: String, body: String, tp: &'static str| {
        let url = format!("{}/v1/streams/support/intents", s.rest);
        async move {
            let res = reqwest::Client::new()
                .post(url)
                .bearer_auth(AGENT)
                .header("idempotency-key", key)
                .header("traceparent", tp)
                .body(body)
                .send()
                .await
                .unwrap();
            (res.status(), res.json::<Value>().await.unwrap())
        }
    };

    let k = id();
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let (st, v) = post_traced(k.clone(), intent("zendesk:ticket/7"), tp).await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert_eq!(
        v["entry"]["trace"],
        json!({"trace_id": trace, "span_id": span})
    );
    let found = q(&s, "target=zendesk:ticket/7").await;
    assert_eq!(found["entries"][0]["entry"]["trace"]["trace_id"], trace);
    assert_eq!(found["entries"][0]["verification"], "verified");

    // A retry comes with a new span: still the same entry.
    let retry = "00-4bf92f3577b34da6a3ce929d0e0e4736-1111111111111111-01";
    let (st, again) = post_traced(k, intent("zendesk:ticket/7"), retry).await;
    assert_eq!((st, &again["entry"]), (StatusCode::OK, &v["entry"]));

    let own = json!({
        "action": {"type": "reply_ticket", "target": "zendesk:ticket/8"},
        "trace": {"trace_id": "0af7651916cd43dd8448eb211c80319c", "span_id": "b7ad6b7169203331"},
    });
    let (_, v) = post_traced(id(), own.to_string(), tp).await;
    assert_eq!(v["entry"]["trace"], own["trace"]);
    let (st, v) = post_traced(id(), intent("zendesk:ticket/9"), "00-bad-01").await;
    assert_eq!(st, StatusCode::CREATED, "{v}");
    assert_eq!(v["entry"].get("trace"), None);

    let mut c = s.grpc().await;
    let mut r = authed(
        AGENT,
        pb::AppendIntentRequest {
            stream: "support".into(),
            idempotency_key: id(),
            draft_json: intent("zendesk:ticket/10"),
        },
    );
    r.metadata_mut().insert("traceparent", tp.parse().unwrap());
    let a = c
        .append_intent(r)
        .await
        .unwrap()
        .into_inner()
        .appended
        .unwrap();
    let e: Value = serde_json::from_str(&a.entry_json).unwrap();
    assert_eq!(e["trace"]["span_id"], span);

    s.stop().await;
    std::fs::remove_dir_all(&dir).unwrap();
}
