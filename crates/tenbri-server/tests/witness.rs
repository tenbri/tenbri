//! Witness cosignatures (Experimental): tenbrid sends checkpoints to a C2SP witness, receipts
//! carry the cosignature, and a forked checkpoint gets none.
#![cfg(feature = "witness")]

use std::sync::Arc;

use serde_json::json;
use tenbri_anchor::test_witness::TestWitness;
use tenbri_anchor::witness::{Added, add_checkpoint};
use tenbri_core::Code;
use tenbri_keys::{Backend, Key, KeyStore, SESSION_LIFETIME_MS};
use tenbri_merkle::{Checkpoint, receipt, witness};
use tenbri_server::{Config, Daemon, Op, WitnessUrl};
use tenbri_store::LocalStore;
use tenbri_writer::{Writer, new_id, now_ms};

const TOKEN: &str = "tnbt_witness";

#[tokio::test(flavor = "multi_thread")]
async fn witnessed_receipts_and_forks() {
    let w = Arc::new(TestWitness::new("witness.test/w1", [5; 32]));
    let url = w.clone().serve().await.unwrap();
    let pinned = w.witness();

    let dir = std::env::temp_dir().join(format!("tenbrid-witness-{}", std::process::id()));
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
        "keys = \"keys\"\n[streams.support]\npath = \"audit/support\"\n\
         [witness]\nwitnesses = [{{ url = \"{url}\", vkey = \"{}\" }}]\n\
         [[tokens]]\nsha256 = \"{}\"\nprincipal = {{ kind = \"agent\", id = \"a\" }}\n",
        pinned.vkey(),
        tenbri_core::sign::sha256(TOKEN.as_bytes())
    );
    let config = Config::parse(&text, &dir, |_| None).unwrap();
    let daemon = Daemon::open(&config).await.unwrap();
    // The operator registers the stream's checkpoint key with the witness.
    let ck = ks.checkpoint_key().unwrap();
    w.add_log(&id, ck.verifying_key());
    let witnesses: Vec<WitnessUrl> = config.witness.clone().unwrap().witnesses;

    let token = daemon
        .authenticate(Some(&format!("Bearer {TOKEN}")))
        .unwrap();
    let first = new_id(now_ms()).unwrap();
    let draft = json!({"action": {"type": "reply_ticket", "target": "t:1"}});
    let draft = serde_json::to_vec(&draft).unwrap();
    daemon
        .append(&token, "support", Op::Intent, Some(&first), &draft, None)
        .await
        .unwrap();
    // A receipt seals a checkpoint: genesis, the session certificates (one with the checkpoint
    // key in its `ext`) and the intent.
    let r = daemon.receipt(&token, "support", &first).await.unwrap();
    let v = receipt::verify(&r, &pin).unwrap();
    let size = v.checkpoint.size;
    assert_eq!(
        witness::checkpoint_key(&v.entries, size),
        Some(ck.verifying_key())
    );
    let e = witness::verify(&v, std::slice::from_ref(&pinned), 1).unwrap_err();
    assert_eq!(e.code, Code::Unwitnessed, "{e}");

    // What [witness] runs every 5 minutes: the witness cosigns the latest checkpoint, once.
    let written = daemon.witness(&witnesses).await;
    assert_eq!(
        written,
        vec![format!("cosignatures/{size:012}/{}.sig", pinned.key_id())]
    );
    assert!(daemon.witness(&witnesses).await.is_empty());
    assert_eq!(w.size(&id), Some(size));

    let r = daemon.receipt(&token, "support", &first).await.unwrap();
    let v = receipt::verify(&r, &pin).unwrap();
    let cosigned = witness::verify(&v, std::slice::from_ref(&pinned), 1).unwrap();
    assert_eq!(cosigned[0].name, "witness.test/w1");
    // Another witness's key: not enough.
    let other = TestWitness::new("witness.test/w2", [6; 32]).witness();
    let e = witness::verify(&v, &[pinned.clone(), other], 2).unwrap_err();
    assert_eq!(e.code, Code::Unwitnessed);
    // A changed cosignature fails even when one would do.
    let text = String::from_utf8(r.to_vec()).unwrap();
    let line = text.find("witness.test/w1 ").unwrap() + "witness.test/w1 ".len();
    let mut forged = text.clone();
    forged.replace_range(
        line + 8..line + 9,
        if &text[line + 8..line + 9] == "A" {
            "B"
        } else {
            "A"
        },
    );
    let v2 = receipt::verify(forged.as_bytes(), &pin).unwrap();
    let e = witness::verify(&v2, std::slice::from_ref(&pinned), 1).unwrap_err();
    assert_eq!(e.code, Code::Unwitnessed, "{e}");

    // A key holder forks the stream: another history of the same size, signed by the same keys.
    // The witness refuses it, so no receipt over it can carry its cosignature.
    let session = Key::new_session(now_ms(), SESSION_LIFETIME_MS).unwrap();
    let forked: Vec<[u8; 32]> = (0..size).map(|i| [i as u8 + 1; 32]).collect();
    let note = Checkpoint::new(&id, &forked).sign_with(&[&session.signing, &ck]);
    let e = add_checkpoint(&url, &pinned, size, &[], &note)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("422"), "{e}");
    // ...and from scratch, the witness says where it is.
    let r = add_checkpoint(&url, &pinned, 0, &[], &note).await.unwrap();
    assert_eq!(r, Added::Conflict(size));
    let _ = std::fs::remove_dir_all(&dir);
}
