//! `tenbri erase` and `tenbri keys` through the binary: a body and a digest for a subject, the
//! erasure refused without confirmation, then done, and the stream still verifying.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use tenbri_crypt::DataKeys;
use tenbri_keys::KeyStore;
use tenbri_store::LocalStore;

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

#[tokio::test(flavor = "current_thread")]
async fn erase_and_keys() {
    let t = std::env::temp_dir().join(format!("tenbri-cli-erase-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&t);
    let (keys, s) = (t.join("keys"), t.join("audit").join("support"));
    let st = s.to_str().unwrap();

    let o = tenbri(&keys, &["init", st], "");
    assert!(o.status.success(), "{o:?}");
    let text = out(&o);
    let fp = text
        .lines()
        .find_map(|l| l.strip_prefix("stream key fingerprint (pin it): "))
        .unwrap();
    let stream = text
        .lines()
        .find_map(|l| l.strip_prefix("created stream "))
        .and_then(|l| l.split(' ').next())
        .unwrap();

    // An integration seals the body and digests the input with the stream's data keys.
    let data = DataKeys::open(&KeyStore::open(&keys, &s, stream).unwrap()).unwrap();
    let store = LocalStore::open(&s).unwrap();
    let body = data
        .seal_body(&store, Some("cust_42"), b"Refund approved")
        .await
        .unwrap();
    let digest = data.digest(Some("cust_42"), b"ticket 4821 text").unwrap();
    let draft = format!(
        r#"{{"kind":"note","subject":"cust_42","body":"{body}","inputs":[{{"ref":"ticket:4821","version":"1","digest":"{digest}"}}]}}"#
    );
    let o = tenbri(&keys, &["append", st], &draft);
    assert!(o.status.success(), "{o:?}");

    let o = tenbri(
        &keys,
        &["keys", "rotate", st, "--tenant", "--by", "ops"],
        "",
    );
    assert!(out(&o).contains("tenant: new data key epoch 1"), "{o:?}");
    let o = tenbri(&keys, &["keys", "list", st], "");
    let text = out(&o);
    assert!(text.contains("subject cust_42: epochs 1..1"), "{text}");
    assert!(text.contains(" stream ed25519:"), "{text}");
    assert!(!text.contains("\"key\""), "list never prints a secret");
    let o = tenbri(
        &keys,
        &["keys", "export", st, "--subject", "cust_42", "--digest"],
        "",
    );
    assert!(out(&o).contains("\"digest_key\""), "{o:?}");
    assert_eq!(
        tenbri(&keys, &["keys", "export", st], "").status.code(),
        Some(2),
        "export needs --subject or --tenant"
    );

    // Not confirmed: nothing is erased or written.
    let erase = [
        "erase",
        st,
        "--subject",
        "cust_42",
        "--reason",
        "dsr:2026-1042",
    ];
    let o = tenbri(&keys, &erase, "cust_4\n");
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    assert!(data.export(Some("cust_42"), false).is_ok());

    let o = tenbri(&keys, &erase, "cust_42\n");
    assert!(o.status.success(), "{o:?}");
    assert!(
        out(&o).contains("1 data key epochs deleted; erasure recorded at seq 5"),
        "{o:?}"
    );

    let o = tenbri(&keys, &["verify", st, "--key", fp], "");
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    assert!(out(&o).starts_with("verified 5 entries"), "{o:?}");
    let o = tenbri(&keys, &["keys", "export", st, "--subject", "cust_42"], "");
    assert_eq!(o.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("erased"),
        "{o:?}"
    );
    let o = tenbri(
        &keys,
        &["query", st, "--action", "tenbri.erase", "--key", fp],
        "",
    );
    assert!(out(&o).contains(r#""subject":"cust_42""#), "{o:?}");
    assert!(out(&o).contains(r#""target":"dsr:2026-1042""#), "{o:?}");

    std::fs::remove_dir_all(&t).unwrap();
}
