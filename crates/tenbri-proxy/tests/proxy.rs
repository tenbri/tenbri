//! The proxy between a client and a server on in-memory pipes, writing to a local stream.

use std::sync::Arc;

use serde_json::{Value, json};
use tenbri_bindings::{Options, Stream};
use tokio::io::{
    AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf, WriteHalf,
};

/// One end of a pipe: what the client or the server sees.
struct End {
    w: WriteHalf<DuplexStream>,
    r: Lines<BufReader<ReadHalf<DuplexStream>>>,
}

impl End {
    fn new(d: DuplexStream) -> End {
        let (r, w) = tokio::io::split(d);
        End {
            w,
            r: BufReader::new(r).lines(),
        }
    }
    async fn send(&mut self, m: Value) {
        self.w.write_all(format!("{m}\n").as_bytes()).await.unwrap();
    }
    async fn recv(&mut self) -> Value {
        serde_json::from_str(&self.r.next_line().await.unwrap().unwrap()).unwrap()
    }
}

async fn stream(name: &str) -> Arc<Stream> {
    let dir = std::env::temp_dir().join(format!("tenbri-proxy-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let o = Options {
        keys: Some(dir.join("keys")),
        create: true,
        ..Options::default()
    };
    Arc::new(
        Stream::open(dir.join("s").to_str().unwrap(), o)
            .await
            .unwrap(),
    )
}

/// A proxy writing to `stream`: the client's end, the server's end, and the proxy's task.
fn proxy(stream: Arc<Stream>) -> (End, End, tokio::task::JoinHandle<std::io::Result<()>>) {
    let (client, at_client) = tokio::io::duplex(1 << 16);
    let (server, at_server) = tokio::io::duplex(1 << 16);
    let (cr, cw) = tokio::io::split(at_client);
    let (sr, sw) = tokio::io::split(at_server);
    let p = tenbri_proxy::principal("agent:support");
    let task = tokio::spawn(tenbri_proxy::run(stream, p, cr, cw, sw, sr));
    (End::new(client), End::new(server), task)
}

fn call(id: Value, tool: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {}}})
}

async fn decisions(s: &Stream) -> Vec<Value> {
    let q: Value = serde_json::from_str(&s.query(b"{}").await.unwrap()).unwrap();
    q.as_array()
        .unwrap()
        .iter()
        .map(|e| e["entry"].clone())
        .filter(|e| e["kind"] == "decision")
        .collect()
}

#[tokio::test]
async fn records_each_call_from_the_wire() {
    let s = stream("wire").await;
    let (mut client, mut server, task) = proxy(s.clone());

    // Not a tool call: passes through unrecorded.
    client
        .send(json!({"jsonrpc": "2.0", "id": 0, "method": "tools/list"}))
        .await;
    assert_eq!(server.recv().await["method"], "tools/list");

    // The intent is durable before the server sees the call.
    client.send(call(json!(1), "reply_ticket")).await;
    assert_eq!(server.recv().await["params"]["name"], "reply_ticket");
    let d = decisions(&s).await;
    assert_eq!(d.len(), 1);
    assert_eq!(
        (&d[0]["phase"], &d[0]["source"]),
        (&json!("intent"), &json!("proxy"))
    );
    assert_eq!(d[0]["action"]["type"], "reply_ticket");
    assert_eq!(d[0]["principal"]["id"], "support");
    server
        .send(json!({"jsonrpc": "2.0", "id": 1, "result": {"content": []}}))
        .await;
    assert_eq!(client.recv().await["id"], 1);

    // A result with isError is an error; "1" is another call than 1.
    client.send(call(json!("1"), "issue_refund")).await;
    server.recv().await;
    server
        .send(json!({"jsonrpc": "2.0", "id": "1", "result": {"isError": true}}))
        .await;
    client.recv().await;

    // A batch holding a call is refused whole.
    client.send(json!([call(json!(2), "issue_refund")])).await;
    let r = client.recv().await;
    assert_eq!(r[0]["error"]["code"], tenbri_proxy::NOT_RECORDED);

    // The client hangs up with two calls out: the server still answers one, then exits.
    client.send(call(json!(3), "close_ticket")).await;
    client.send(call(json!(4), "delete_account")).await;
    server.recv().await;
    server.recv().await;
    drop(client);
    server
        .send(json!({"jsonrpc": "2.0", "id": 3, "result": {}}))
        .await;
    drop(server);
    task.await.unwrap().unwrap();

    let d = decisions(&s).await;
    let outcomes: Vec<(&Value, &Value)> = d
        .iter()
        .filter(|e| e["phase"] == "outcome")
        .map(|e| (&e["action"]["type"], &e["status"]))
        .collect();
    assert_eq!(
        outcomes,
        [
            (&json!("reply_ticket"), &json!("ok")),
            (&json!("issue_refund"), &json!("error")),
            (&json!("close_ticket"), &json!("ok")),
            (&json!("delete_account"), &json!("unknown")),
        ]
    );
    assert!(d.iter().all(|e| e["source"] == "proxy"));
}

#[tokio::test]
async fn refuses_a_call_it_cannot_record() {
    let s = stream("closed").await;
    s.close().await;
    let (mut client, mut server, _task) = proxy(s);
    client.send(call(json!(7), "issue_refund")).await;
    let r = client.recv().await;
    assert_eq!(
        (&r["id"], &r["error"]["code"]),
        (&json!(7), &json!(tenbri_proxy::NOT_RECORDED))
    );
    // The server never saw it: the next thing it gets is the next message.
    client
        .send(json!({"jsonrpc": "2.0", "id": 8, "method": "ping"}))
        .await;
    assert_eq!(server.recv().await["id"], 8);
}

#[tokio::test]
async fn pins_the_arguments_by_keyed_digest() {
    let s = stream("args").await;
    let (mut client, mut server, _task) = proxy(s.clone());
    let with = |id: i64, args: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"issue_refund","arguments":{args}}}}}"#
        )
    };
    // Nested key order as sent does not change the digest; numbers past f64 stay distinct.
    for (id, args) in [
        (
            1,
            r#"{"b": {"y": 1, "x": [{"q": 2, "p": "éé"}]}, "a": 18446744073709551616}"#,
        ),
        (
            2,
            r#"{"a":18446744073709551616,"b":{"x":[{"p":"éé","q":2}],"y":1}}"#,
        ),
        (
            3,
            r#"{"a":18446744073709551617,"b":{"x":[{"p":"éé","q":2}],"y":1}}"#,
        ),
    ] {
        client
            .w
            .write_all(format!("{}\n", with(id, args)).as_bytes())
            .await
            .unwrap();
        server.recv().await;
    }
    // No arguments, no input.
    client
        .send(
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "ping"}}),
        )
        .await;
    server.recv().await;
    // A repeated key: which one the server reads is its choice, so the call is refused.
    client
        .w
        .write_all(format!("{}\n", with(5, r#"{"a":1,"a":2}"#)).as_bytes())
        .await
        .unwrap();
    let r = client.recv().await;
    assert_eq!(
        (&r["id"], &r["error"]["code"]),
        (&json!(5), &json!(tenbri_proxy::NOT_RECORDED))
    );

    let d = decisions(&s).await;
    let digest = |i: usize| d[i]["inputs"][0]["digest"].clone();
    assert_eq!(
        d[0]["inputs"],
        json!([{
            "ref": "mcp:issue_refund/arguments",
            "version": tenbri_proxy::ARGUMENTS_VERSION,
            "digest": s
                .digest(None, r#"{"a":18446744073709551616,"b":{"x":[{"p":"éé","q":2}],"y":1}}"#.as_bytes())
                .await
                .unwrap(),
        }])
    );
    assert_eq!(digest(1), digest(0));
    assert_ne!(digest(2), digest(0), "another number, another digest");
    assert!(d[3].get("inputs").is_none(), "{}", d[3]);
    assert_eq!(d.len(), 4, "the refused call has no intent");
}

/// Through a tenbrid that will not digest for its token, a call with arguments is refused (and a
/// call without passes): an unpinned call is never run.
#[tokio::test]
async fn refuses_a_call_whose_arguments_it_cannot_digest() {
    use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
    let dir = std::env::temp_dir().join(format!("tenbri-proxy-remote-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("audit");
    std::fs::create_dir_all(&path).unwrap();
    let stream_key = Key::new_stream().unwrap();
    let session = Key::new_session(tenbri_writer::now_ms(), SESSION_LIFETIME_MS).unwrap();
    let id = tenbri_core::sign::stream_id(&stream_key.signing.verifying_key());
    let ks = KeyStore::open(&dir.join("keys"), &path, &id).unwrap();
    ks.save(&stream_key, Backend::File).unwrap();
    ks.save(&session, Backend::File).unwrap();
    tenbri_writer::Writer::create(
        tenbri_store::LocalStore::open(&path).unwrap(),
        &stream_key,
        session,
    )
    .await
    .unwrap();
    let token = "tnbt_proxy_no_digest";
    let config = format!(
        "keys = \"keys\"\nindex_dir = \"index\"\n[streams.support]\npath = \"audit\"\n\
         [[tokens]]\nsha256 = \"{}\"\nprincipal = {{ kind = \"agent\", id = \"support\" }}\n",
        tenbri_core::sign::sha256(token.as_bytes())
    );
    let daemon = Arc::new(
        tenbri_server::Daemon::open(
            &tenbri_server::Config::parse(&config, &dir, |_| None).unwrap(),
        )
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
    let o = Options {
        token: Some(token.into()),
        ..Options::default()
    };
    let s = Arc::new(Stream::open(&url, o).await.unwrap());

    let (mut client, mut server, _task) = proxy(s);
    client.send(call(json!(1), "issue_refund")).await;
    let r = client.recv().await;
    assert_eq!(
        (&r["id"], &r["error"]["code"]),
        (&json!(1), &json!(tenbri_proxy::NOT_RECORDED))
    );
    assert!(
        r["error"]["message"].as_str().unwrap().contains("digest"),
        "{r}"
    );
    client
        .send(
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ping"}}),
        )
        .await;
    assert_eq!(server.recv().await["id"], 2, "the server never saw call 1");
}
