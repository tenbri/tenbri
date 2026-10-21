//! A stream key in a PKCS#11 token, through the binary: init, session renewal, rotation, verify.
//! Runs when `TENBRI_TEST_PKCS11_MODULE`, `TENBRI_TEST_PKCS11_TOKEN` and `TENBRI_TEST_PKCS11_PIN`
//! name a token (SoftHSM in CI).
#![cfg(feature = "pkcs11")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// `TENBRI_PKCS11_*` for the binary, from `TENBRI_TEST_PKCS11_*`, if this run has a token.
fn token_env() -> Option<Vec<(String, String)>> {
    ["MODULE", "TOKEN", "PIN"]
        .iter()
        .map(|k| {
            let v = std::env::var(format!("TENBRI_TEST_PKCS11_{k}")).ok()?;
            Some((format!("TENBRI_PKCS11_{k}"), v))
        })
        .collect()
}

fn tenbri(keys: &Path, env: &[(String, String)], args: &[&str], stdin: &str) -> Output {
    use std::io::Write;
    let mut c = Command::new(env!("CARGO_BIN_EXE_tenbri"))
        .envs(env.iter().map(|(k, v)| (k, v)))
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

fn ok(o: Output) -> String {
    assert!(o.status.success(), "{o:?}");
    String::from_utf8(o.stdout).unwrap()
}

/// The key descriptions and secret files of the one stream under `keys`.
fn key_files(keys: &Path) -> (Vec<serde_json::Value>, Vec<PathBuf>) {
    let dir = std::fs::read_dir(keys)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap();
    let files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let metas = files
        .iter()
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap())
        .collect();
    let secrets = files
        .into_iter()
        .filter(|p| p.extension().is_some_and(|x| x == "secret"))
        .collect();
    (metas, secrets)
}

fn fingerprint(init: &str) -> String {
    init.lines()
        .find_map(|l| l.strip_prefix("stream key fingerprint (pin it): "))
        .unwrap()
        .to_owned()
}

const NOTE: &str = r#"{"kind":"note","source":"sdk","principal":{"kind":"person","id":"ops"}}"#;

#[test]
fn a_token_keeps_the_stream_key_through_init_renewal_and_rotation() {
    let Some(env) = token_env() else {
        eprintln!("TENBRI_TEST_PKCS11_* not set: no PKCS#11 token in this run");
        return;
    };
    let t = std::env::temp_dir().join(format!("tenbri-cli-pkcs11-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&t);
    let (keys, s) = (t.join("keys"), t.join("audit").join("support"));
    let st = s.to_str().unwrap();

    let o = tenbri(&keys, &env, &["init", st, "--pkcs11"], "");
    assert_eq!(
        o.status.code(),
        Some(2),
        "Experimental needs --experimental"
    );
    let fp = fingerprint(&ok(tenbri(
        &keys,
        &env,
        &["init", st, "--pkcs11", "--experimental"],
        "",
    )));
    // On this machine: the stream key's description, and a session key; no stream key secret.
    let (metas, secrets) = key_files(&keys);
    let stream: Vec<_> = metas.iter().filter(|m| m["role"] == "stream").collect();
    assert_eq!(
        (stream.len(), stream[0]["backend"].as_str()),
        (1, Some("pkcs11"))
    );
    assert_eq!(secrets.len(), 1, "the session key only");
    ok(tenbri(&keys, &env, &["append", st], NOTE));

    // The session key gone (as after it expires): the token certifies a new one.
    for p in secrets {
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_file(p.with_extension("json")).unwrap();
    }
    let o = tenbri(&keys, &[], &["append", st], NOTE);
    assert!(!o.status.success(), "no token, no new session: {o:?}");
    ok(tenbri(&keys, &env, &["append", st], NOTE));

    // Rotation to a new key in the token, signed by the old one.
    let o = tenbri(&keys, &env, &["keys", "rotate-stream", st], "");
    assert_eq!(
        o.status.code(),
        Some(2),
        "Experimental needs --experimental"
    );
    let r = ok(tenbri(
        &keys,
        &env,
        &["keys", "rotate-stream", st, "--experimental"],
        "",
    ));
    assert!(r.contains("(PKCS#11)"), "{r}");
    ok(tenbri(&keys, &env, &["append", st], NOTE));
    // Reading needs no token, even with the module named alone.
    let module = env[..1].to_vec();
    let v = ok(tenbri(&keys, &module, &["verify", st, "--key", &fp], ""));
    assert!(v.starts_with("verified 7 entries"), "{v}");

    // A stolen session key, revoked by the token from the entry it started at: the stream stops
    // verifying there, as it should.
    let stolen = key_files(&keys)
        .0
        .into_iter()
        .filter(|m| m["role"] == "session")
        .map(|m| m["id"].as_str().unwrap().to_owned())
        .max()
        .unwrap();
    let revoke = [
        "keys",
        "revoke",
        st,
        &stolen,
        "--from",
        "7",
        "--experimental",
    ];
    let o = tenbri(&keys, &env, &revoke, "no\n");
    assert_eq!(o.status.code(), Some(2), "not confirmed: {o:?}");
    ok(tenbri(&keys, &env, &revoke, &format!("{stolen}\n")));
    let o = tenbri(&keys, &[], &["verify", st, "--key", &fp], "");
    assert!(format!("{o:?}").contains("key_revoked"), "{o:?}");

    // An existing stream moves its stream key into the token by rotating.
    let (keys2, s2) = (t.join("keys2"), t.join("audit").join("billing"));
    let st2 = s2.to_str().unwrap();
    let fp2 = fingerprint(&ok(tenbri(&keys2, &[], &["init", st2], "")));
    ok(tenbri(
        &keys2,
        &env,
        &["keys", "rotate-stream", st2, "--experimental"],
        "",
    ));
    ok(tenbri(&keys2, &env, &["append", st2], NOTE));
    ok(tenbri(&keys2, &[], &["verify", st2, "--key", &fp2], ""));
    std::fs::remove_dir_all(&t).unwrap();
}
