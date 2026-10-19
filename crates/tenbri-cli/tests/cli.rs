//! init → append → verify → query → tail → tamper → verify fails, through the binary.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn tenbri(keys: &Path, args: &[&str], stdin: &str) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_tenbri"))
        .arg("--keys")
        .arg(keys)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    c.wait_with_output().unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn round_trip() {
    let t = std::env::temp_dir().join(format!("tenbri-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&t);
    let (keys, s) = (t.join("keys"), t.join("audit").join("support"));
    let st = s.to_str().unwrap();

    let o = tenbri(&keys, &["init", st], "");
    assert!(o.status.success(), "{o:?}");
    let fp = out(&o)
        .lines()
        .find_map(|l| l.strip_prefix("stream key fingerprint (pin it): "))
        .unwrap()
        .to_owned();
    assert!(
        !tenbri(&keys, &["init", st], "").status.success(),
        "init refuses a used directory"
    );
    // Keys never under the stream root.
    let nested = t.join("nested");
    let o = tenbri(
        &nested.join("keys"),
        &["init", nested.to_str().unwrap()],
        "",
    );
    assert_eq!(o.status.code(), Some(2), "{o:?}");

    let intent = r#"{"kind":"decision","phase":"intent","source":"sdk","principal":{"kind":"agent","id":"a"},"action":{"type":"reply_ticket","target":"t:1"},"inputs":[{"ref":"policy:refund","version":"14","digest":"hmac-sha256:9f2c41aa9f2c41aa9f2c41aa9f2c41aa9f2c41aa9f2c41aa9f2c41aa9f2c41aa"}]}"#;
    let o = tenbri(&keys, &["append", st], intent);
    assert!(o.status.success(), "{o:?}");
    let stored: serde_json::Value = serde_json::from_str(out(&o).trim()).unwrap();
    let id = stored["id"].as_str().unwrap();
    let outcome = format!(
        r#"{{ "kind":"decision","phase":"outcome","source":"sdk","intent":"{id}","status":"ok","principal":{{"kind":"agent","id":"a"}},"action":{{"type":"reply_ticket"}} }}"#
    );
    assert!(tenbri(&keys, &["append", st], &outcome).status.success());
    // Bad input is refused, and nothing is written.
    for bad in [
        r#"{"kind":"note","seq":9}"#,
        r#"{"kind":"note","kind":"note"}"#,
        r#"{"kind":"note","ext":{"x":1.5}}"#,
        "not json",
    ] {
        assert_eq!(
            tenbri(&keys, &["append", st], bad).status.code(),
            Some(2),
            "{bad}"
        );
    }

    let o = tenbri(&keys, &["verify", st, "--key", &fp], "");
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(out(&o).starts_with("verified 4 entries"));
    assert_eq!(
        tenbri(&keys, &["verify", st], "").status.code(),
        Some(3),
        "unpinned"
    );

    let o = tenbri(
        &keys,
        &["query", st, "--input", "policy:refund@14", "--key", &fp],
        "",
    );
    let text = out(&o);
    let rows: Vec<&str> = text.lines().collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].starts_with(r#"{"verification":"verified","entry":{"#));
    assert_eq!(
        out(&tenbri(
            &keys,
            &["query", st, "--action", "reply_ticket"],
            ""
        ))
        .lines()
        .count(),
        2
    );
    assert_eq!(
        out(&tenbri(&keys, &["tail", st, "-n", "2", "--no-follow"], ""))
            .lines()
            .count(),
        2
    );

    // Edit one byte of entry 3: verification fails there, with exit code 1.
    let batch = s.join("batches").join("000000000003.jsonl");
    let text = std::fs::read_to_string(&batch).unwrap();
    std::fs::write(&batch, text.replace("t:1", "t:2")).unwrap();
    let o = tenbri(&keys, &["verify", st, "--key", &fp], "");
    assert_eq!(o.status.code(), Some(1));
    assert!(
        out(&o).starts_with("broken at seq 3: bad_signature"),
        "{}",
        out(&o)
    );
    assert_eq!(
        tenbri(
            &keys,
            &["query", st, "--action", "reply_ticket", "--key", &fp],
            ""
        )
        .status
        .code(),
        Some(1)
    );
    std::fs::remove_dir_all(&t).unwrap();
}

/// `verify --checkpoint` on the stream cases of spec/vectors/checkpoints.json, each laid out on
/// disk with one entry per batch and a HEAD signed by `sess:a1`.
#[test]
fn verify_against_checkpoints() {
    use tenbri_core::sign::{SigningKey, entry_hash, sha256, sign_head};
    let v: serde_json::Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/checkpoints.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let seed = sha256(b"tenbri vector key s1");
    let s1 =
        SigningKey::from_bytes(&tenbri_core::encoding::prefixed::<32>(&seed, "sha256:").unwrap());
    let t = std::env::temp_dir().join(format!("tenbri-cli-cp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&t);
    let keys = t.join("keys");
    let case = |name: &str| {
        let c = v["streams"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap()
            .clone();
        let dir = t.join(name);
        std::fs::create_dir_all(dir.join("batches")).unwrap();
        let lines: Vec<&str> = c["lines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect();
        for (i, l) in lines.iter().enumerate() {
            std::fs::write(
                dir.join(format!("batches/{:012}.jsonl", i + 1)),
                format!("{l}\n"),
            )
            .unwrap();
        }
        let n = lines.len() as u64;
        let mut head = tenbri_core::Head {
            v: 1,
            stream: c["checkpoint"]
                .as_str()
                .unwrap()
                .lines()
                .next()
                .unwrap()
                .to_owned(),
            seq: n,
            hash: entry_hash(lines[n as usize - 1].as_bytes()),
            counter: n,
            batch: n,
            signer: "sess:a1".into(),
            sig: String::new(),
        };
        std::fs::write(dir.join("HEAD"), sign_head(&mut head, &s1)).unwrap();
        std::fs::write(dir.join("cp.note"), c["checkpoint"].as_str().unwrap()).unwrap();
        (dir, c["pin"].as_str().unwrap().to_owned())
    };
    let run = |dir: &Path, pin: Option<&str>| {
        let (st, cp) = (dir.to_str().unwrap(), dir.join("cp.note"));
        let mut args = vec!["verify", st, "--checkpoint", cp.to_str().unwrap()];
        args.extend(pin.map(|p| ["--key", p]).into_iter().flatten());
        tenbri(&keys, &args, "")
    };

    let (dir, pin) = case("checkpoint-behind-head");
    let o = run(&dir, Some(&pin));
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(
        out(&o).starts_with("matches checkpoint tnb1:"),
        "{}",
        out(&o)
    );
    assert_eq!(
        run(&dir, None).status.code(),
        Some(3),
        "a checkpoint does not replace --key"
    );

    let (dir, pin) = case("truncation-behind-checkpoint");
    assert_eq!(
        tenbri(&keys, &["verify", dir.to_str().unwrap(), "--key", &pin], "")
            .status
            .code(),
        Some(0),
        "the truncated stream verifies on its own"
    );
    let o = run(&dir, Some(&pin));
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert!(
        out(&o).starts_with("broken at seq 9: truncated"),
        "{}",
        out(&o)
    );

    let (dir, pin) = case("rewrite-behind-checkpoint");
    let o = run(&dir, Some(&pin));
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert!(out(&o).starts_with("broken at seq 10: fork"), "{}", out(&o));

    std::fs::write(dir.join("cp.note"), "not a checkpoint").unwrap();
    assert_eq!(
        run(&dir, Some(&pin)).status.code(),
        Some(2),
        "a malformed checkpoint"
    );
    std::fs::remove_dir_all(&t).unwrap();
}
