//! checkpoint --tsa → receipt create → receipt verify, offline, against the pinned key and TSA root.

use std::path::Path;
use std::process::{Command, Output};

use tenbri_anchor::test_tsa::TestTsa;

fn tenbri(keys: &Path, args: &[&str], stdin: &str) -> Output {
    use std::io::Write;
    let mut c = Command::new(env!("CARGO_BIN_EXE_tenbri"))
        .arg("--keys")
        .arg(keys)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    c.wait_with_output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
}

#[tokio::test(flavor = "multi_thread")]
async fn receipts_with_a_timestamp() {
    let tsa = TestTsa::new(b"\x07 cli");
    let root_pem = tsa.root_pem();
    let url = tsa.serve().await.unwrap();

    let t = std::env::temp_dir().join(format!("tenbri-receipt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&t);
    let (keys, s) = (t.join("keys"), t.join("audit").join("support"));
    let st = s.to_str().unwrap();
    let o = tenbri(&keys, &["init", st], "");
    let fp = out(&o)
        .lines()
        .find_map(|l| l.strip_prefix("stream key fingerprint (pin it): "))
        .unwrap()
        .to_owned();
    let intent = r#"{"kind":"decision","phase":"intent","source":"sdk","principal":{"kind":"agent","id":"a"},"action":{"type":"reply_ticket","target":"t:1"}}"#;
    let o = tenbri(&keys, &["append", st], intent);
    let stored: serde_json::Value = serde_json::from_str(out(&o).trim()).unwrap();
    let id = stored["id"].as_str().unwrap().to_owned();

    // No checkpoint covers it yet.
    let o = tenbri(&keys, &["receipt", "create", st, "--entry", &id], "");
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(out(&o).contains("no checkpoint covers"), "{}", out(&o));

    let o = tenbri(&keys, &["checkpoint", st, "--tsa", &url], "");
    assert!(o.status.success(), "{}", out(&o));
    assert!(s.join("anchors/000000000003.tsr").exists());
    // Again: nothing new to seal, already timestamped.
    let o = tenbri(&keys, &["checkpoint", st, "--tsa", &url], "");
    assert!(out(&o).contains("already timestamped"), "{}", out(&o));

    let file = t.join("receipt.json");
    let f = file.to_str().unwrap();
    let o = tenbri(
        &keys,
        &[
            "receipt", "create", st, "--entry", &id, "--out", f, "--key", &fp,
        ],
        "",
    );
    assert!(o.status.success(), "{}", out(&o));

    let o = tenbri(&keys, &["receipt", "verify", f, "--key", &fp], "");
    assert!(o.status.success(), "{}", out(&o));
    assert!(
        out(&o).contains("proves seq 3 (decision intent)"),
        "{}",
        out(&o)
    );
    assert!(out(&o).contains("NOT checked"), "{}", out(&o));

    let roots = t.join("tsa.pem");
    std::fs::write(&roots, &root_pem).unwrap();
    let r = roots.to_str().unwrap();
    let o = tenbri(
        &keys,
        &["receipt", "verify", f, "--key", &fp, "--tsa-roots", r],
        "",
    );
    assert!(out(&o).contains("timestamped by"), "{}", out(&o));
    assert!(o.status.success());

    // Another TSA root: the token does not chain.
    std::fs::write(&roots, TestTsa::new(b"\x08 other").root_pem()).unwrap();
    let o = tenbri(
        &keys,
        &["receipt", "verify", f, "--key", &fp, "--tsa-roots", r],
        "",
    );
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("bad_timestamp"), "{}", out(&o));

    // Another pinned key.
    let other = format!("sha256:{}", "0".repeat(64));
    let o = tenbri(&keys, &["receipt", "verify", f, "--key", &other], "");
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).contains("untrusted_root"), "{}", out(&o));

    // One character changed in the entry.
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, text.replace("reply_ticket", "reply_tickex")).unwrap();
    let o = tenbri(&keys, &["receipt", "verify", f, "--key", &fp], "");
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).contains("bad_signature"), "{}", out(&o));

    // By seq, to stdout; the genesis entry alone.
    let o = tenbri(&keys, &["receipt", "create", st, "--entry", "1"], "");
    std::fs::write(&file, &o.stdout).unwrap();
    let o = tenbri(&keys, &["receipt", "verify", f, "--key", &fp], "");
    assert!(out(&o).contains("proves seq 1 (key)"), "{}", out(&o));
    let o = tenbri(&keys, &["receipt", "create", st, "--entry", "99"], "");
    assert_eq!(o.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&t);
}
