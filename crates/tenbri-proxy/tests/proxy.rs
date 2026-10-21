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
    // Key order as sent does not change the digest.
    client
        .send(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "issue_refund", "arguments": {"charge": "ch_1", "amount": 20}}}))
        .await;
    server.recv().await;
    // No arguments, no input.
    client
        .send(
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ping"}}),
        )
        .await;
    server.recv().await;

    let d = decisions(&s).await;
    assert_eq!(
        d[0]["inputs"],
        json!([{
            "ref": "mcp:issue_refund/arguments",
            "version": tenbri_proxy::ARGUMENTS_VERSION,
            "digest": s.digest(None, br#"{"amount":20,"charge":"ch_1"}"#).await.unwrap(),
        }])
    );
    assert!(d[1].get("inputs").is_none(), "{}", d[1]);
}
