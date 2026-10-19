//! init → append → verify → query → tail → tamper → verify fails, through the binary.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn tenbri(keys: &Path, args: &[&str], stdin: &str) -> Output {
    tenbri_env(keys, args, stdin, &[])
}

fn tenbri_env(keys: &Path, args: &[&str], stdin: &str, env: &[(&str, String)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_tenbri"))
        .envs(env.iter().map(|(k, v)| (k, v)))
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

/// init → append → verify on an S3-compatible bucket, when `TENBRI_TEST_S3_*` is set (MinIO in
/// CI): the binary takes its credentials from the `AWS_*` variables.
#[test]
fn s3_round_trip() {
    let var = |k: &str| {
        std::env::var(format!("TENBRI_TEST_S3_{k}"))
            .ok()
            .filter(|v| !v.is_empty())
    };
    let Some(bucket) = var("BUCKET") else {
        eprintln!("TENBRI_TEST_S3_* not set: skipped");
        return;
    };
    let mut env = vec![
        ("AWS_ACCESS_KEY_ID", var("ACCESS_KEY_ID").unwrap()),
        ("AWS_SECRET_ACCESS_KEY", var("SECRET_ACCESS_KEY").unwrap()),
        (
            "AWS_REGION",
            var("REGION").unwrap_or_else(|| "us-east-1".into()),
        ),
    ];
    if let Some(e) = var("ENDPOINT") {
        env.push(("AWS_ALLOW_HTTP", e.starts_with("http://").to_string()));
        env.push(("AWS_ENDPOINT_URL", e));
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let url = format!("s3://{bucket}/tenbri-tests/cli-{nanos}/support");
    let keys = std::env::temp_dir().join(format!("tenbri-cli-s3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&keys);
    let run = |args: &[&str], stdin: &str| tenbri_env(&keys, args, stdin, &env);

    let o = run(&["init", &url], "");
    assert!(o.status.success(), "{o:?}");
    let fp = out(&o)
        .lines()
        .find_map(|l| l.strip_prefix("stream key fingerprint (pin it): "))
        .unwrap()
        .to_owned();
    assert_eq!(run(&["init", &url], "").status.code(), Some(2), "used");
    assert!(
        run(&["append", &url], r#"{"kind":"note"}"#)
            .status
            .success()
    );
    let o = run(&["verify", &url, "--key", &fp], "");
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(out(&o).starts_with("verified 3 entries"), "{}", out(&o));
    let o = run(
        &["verify", "s3://no-such-bucket-tenbri/x", "--key", &fp],
        "",
    );
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    std::fs::remove_dir_all(&keys).unwrap();
}
