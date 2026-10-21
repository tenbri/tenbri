//! Experimental: a stream with a checkpoint key, a witness's cosignature next to its checkpoint,
//! and `receipt verify --witness`.
#![cfg(feature = "witness")]

use std::path::Path;
use std::process::{Command, Output};

use tenbri_anchor::test_witness::TestWitness;
use tenbri_core::sign::SigningKey;
use tenbri_merkle::checkpoint;
use tenbri_merkle::witness::request;

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

#[test]
fn receipt_verify_requires_witnesses() {
    let t = std::env::temp_dir().join(format!("tenbri-witness-{}", std::process::id()));
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
    let (id, stream) = (
        stored["id"].as_str().unwrap(),
        stored["stream"].as_str().unwrap(),
    );

    // The stream's checkpoint key, as tenbrid's [witness] makes it.
    let ck = SigningKey::from_bytes(&[9; 32]);
    let dir = keys.join(stream.replace(':', "-"));
    std::fs::write(
        dir.join(tenbri_keys::CHECKPOINT_KEY_FILE),
        tenbri_core::encoding::hex(ck.as_bytes()),
    )
    .unwrap();
    let o = tenbri(&keys, &["checkpoint", st], "");
    assert!(o.status.success(), "{}", out(&o));
    let size: u64 = 4; // genesis, session, intent, the session certifying the checkpoint key
    let note = std::fs::read(s.join(checkpoint::key(size))).unwrap();

    let w = TestWitness::new("witness.test/cli", [3; 32]);
    w.add_log(stream, ck.verifying_key());
    let (status, _, line) = w.add_checkpoint(&request(0, &[], &note), 1_790_000_000);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&line));
    let cosigs = s.join(checkpoint::cosignatures_dir(size));
    std::fs::create_dir_all(&cosigs).unwrap();
    std::fs::write(cosigs.join(format!("{}.sig", w.witness().key_id())), line).unwrap();

    let file = t.join("receipt.json");
    let f = file.to_str().unwrap();
    let o = tenbri(
        &keys,
        &["receipt", "create", st, "--entry", id, "--out", f],
        "",
    );
    assert!(o.status.success(), "{}", out(&o));
    let vkey = w.witness().vkey();
    let o = tenbri(
        &keys,
        &["receipt", "verify", f, "--key", &fp, "--witness", &vkey],
        "",
    );
    assert!(o.status.success(), "{}", out(&o));
    assert!(
        out(&o).contains("cosigned by witness witness.test/cli"),
        "{}",
        out(&o)
    );

    let other = TestWitness::new("witness.test/other", [4; 32])
        .witness()
        .vkey();
    let args = [
        "receipt",
        "verify",
        f,
        "--key",
        &fp,
        "--witness",
        &vkey,
        "--witness",
        &other,
    ];
    let o = tenbri(&keys, &args, "");
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("unwitnessed"), "{}", out(&o));
    let mut one = args.to_vec();
    one.extend(["--witnesses", "1"]);
    assert!(tenbri(&keys, &one, "").status.success());
    let _ = std::fs::remove_dir_all(&t);
}
