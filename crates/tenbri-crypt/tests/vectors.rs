//! spec/vectors/privacy.json: derivation, digests, blobs, and an erased subject's stream.

use serde_json::Value as J;
use tenbri_core::Chain;
use tenbri_core::encoding::{hex, unhex};
use tenbri_crypt::{DataKey, address, blob_key, blob_path, digest, digest_key, open, seal};

fn vectors() -> J {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/privacy.json"
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn s(j: &J) -> &str {
    j.as_str().unwrap()
}

fn key(j: &J) -> DataKey {
    unhex(s(j)).unwrap()
}

fn bytes(j: &J) -> Vec<u8> {
    let h = s(j);
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn derivation_and_digests() {
    let v = vectors();
    for c in v["derivation"].as_array().unwrap() {
        let k = key(&c["data_key"]);
        assert_eq!(hex(&*blob_key(&k)), s(&c["blob_key"]));
        assert_eq!(hex(&*digest_key(&k)), s(&c["digest_key"]));
    }
    for c in v["digests"].as_array().unwrap() {
        let k = key(&c["data_key"]);
        assert_eq!(digest(&k, s(&c["content"]).as_bytes()), s(&c["digest"]));
    }
}

#[test]
fn blobs() {
    let v = vectors();
    for c in v["blobs"]["valid"].as_array().unwrap() {
        let k = key(&c["data_key"]);
        let nonce: [u8; 24] = bytes(&c["nonce"]).try_into().unwrap();
        let blob = seal(&k, s(&c["stream"]), &nonce, s(&c["plaintext"]).as_bytes());
        assert_eq!(blob, bytes(&c["blob"]));
        assert_eq!(address(&blob), s(&c["address"]));
        assert_eq!(blob_path(&address(&blob)).unwrap(), s(&c["path"]));
        assert_eq!(
            &open(&k, s(&c["stream"]), &blob).unwrap()[..],
            s(&c["plaintext"]).as_bytes()
        );
    }
    for c in v["blobs"]["invalid"].as_array().unwrap() {
        let blob = bytes(&c["blob"]);
        let error = if address(&blob) != s(&c["address"]) {
            "address_mismatch"
        } else if open(&key(&c["data_key"]), s(&c["stream"]), &blob).is_none() {
            "not_opened"
        } else {
            "none"
        };
        assert_eq!(error, s(&c["error"]), "{}", s(&c["why"]));
    }
}

#[test]
fn an_erased_subject_still_verifies() {
    let v = &vectors()["erased"];
    let mut chain = Chain::new(Some(s(&v["pin"])));
    let mut entries = vec![];
    for l in v["lines"].as_array().unwrap() {
        entries.push(chain.push(s(l).as_bytes()).unwrap());
    }
    assert_eq!(entries.len() as u64, v["result"]["ok"].as_u64().unwrap());
    let keys = v["keys"].as_object().unwrap();
    for e in entries.iter().filter(|e| e.body.is_some()) {
        let addr = e.body.as_deref().unwrap();
        let blob = bytes(&v["blobs"][addr]);
        assert_eq!(address(&blob), addr);
        let subject = e.subject.as_deref().unwrap();
        match keys.get(subject) {
            Some(k) => assert_eq!(
                &open(&key(k), &e.stream, &blob).unwrap()[..],
                s(&v["bodies"][addr]).as_bytes()
            ),
            None => assert!(v["bodies"][addr].is_null() && v["erased"][0] == subject),
        }
    }
    for i in v["inputs"].as_array().unwrap() {
        let held = keys.get(s(&i["subject"]));
        assert_eq!(held.is_some(), i["confirmable"].as_bool().unwrap());
        if let Some(k) = held {
            assert_eq!(
                digest(&key(k), s(&i["content"]).as_bytes()),
                s(&i["digest"])
            );
        }
    }
    let note = entries.last().unwrap();
    assert_eq!(note.action.as_ref().unwrap().r#type, "tenbri.erase");
}
