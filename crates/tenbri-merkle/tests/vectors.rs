//! spec/vectors/merkle.json and checkpoints.json through the crate.

use serde_json::Value as J;
use tenbri_core::Chain;
use tenbri_core::encoding::prefixed;
use tenbri_core::sign::decode_key;
use tenbri_merkle::tree::{
    consistency_proof, inclusion_proof, root, verify_consistency, verify_inclusion,
};
use tenbri_merkle::{Hash, Note};

fn load(name: &str) -> J {
    let path = format!("{}/../../spec/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn hash(j: &J) -> Hash {
    prefixed::<32>(j.as_str().unwrap(), "sha256:").unwrap()
}

fn hashes(j: &J) -> Vec<Hash> {
    j.as_array().unwrap().iter().map(hash).collect()
}

fn n(j: &J) -> u64 {
    j.as_u64().unwrap()
}

#[test]
fn merkle() {
    let v = load("merkle.json");
    let leaves = hashes(&v["leaves"]);
    for t in v["trees"].as_array().unwrap() {
        assert_eq!(
            root(&leaves[..n(&t["size"]) as usize]),
            hash(&t["root"]),
            "{t}"
        );
    }
    for c in v["inclusion"].as_array().unwrap() {
        let (i, size, proof) = (n(&c["index"]), n(&c["size"]), hashes(&c["proof"]));
        let valid = verify_inclusion(i, size, &hash(&c["leaf"]), &proof, &hash(&c["root"]));
        assert_eq!(valid, c["valid"].as_bool().unwrap(), "{c}");
        if c["name"] == "valid" {
            assert_eq!(inclusion_proof(&leaves[..size as usize], i), Some(proof));
        }
    }
    for c in v["consistency"].as_array().unwrap() {
        let (m, size, proof) = (n(&c["old_size"]), n(&c["new_size"]), hashes(&c["proof"]));
        let valid = verify_consistency(
            m,
            size,
            &hash(&c["old_root"]),
            &hash(&c["new_root"]),
            &proof,
        );
        assert_eq!(valid, c["valid"].as_bool().unwrap(), "{c}");
        if c["name"] == "valid" {
            assert_eq!(consistency_proof(&leaves[..size as usize], m), Some(proof));
        }
    }
}

#[test]
fn notes() {
    let v = load("checkpoints.json");
    for c in v["notes"].as_array().unwrap() {
        let r = &c["result"];
        match Note::parse(c["note"].as_str().unwrap().as_bytes()) {
            Ok(note) => {
                let cp = &note.checkpoint;
                assert_eq!(cp.origin, r["origin"].as_str().unwrap(), "{c}");
                assert_eq!(cp.size, n(&r["size"]), "{c}");
                assert_eq!(cp.root, hash(&r["root"]), "{c}");
                let key = decode_key(c["signer_pub"].as_str().unwrap()).unwrap();
                assert_eq!(note.signed_by(&key), r["signed_by"].as_bool(), "{c}");
            }
            Err(e) => assert_eq!(e.code.as_str(), r["error"], "{c}"),
        }
    }
}

#[test]
fn streams() {
    let v = load("checkpoints.json");
    for c in v["streams"].as_array().unwrap() {
        let mut chain = Chain::new(c["pin"].as_str());
        let mut leaves = vec![];
        for l in c["lines"].as_array().unwrap() {
            let l = l.as_str().unwrap();
            chain.push(l.as_bytes()).unwrap();
            leaves.push(hash(&tenbri_core::sign::entry_hash(l.as_bytes()).into()));
        }
        assert!(chain.invalidated().is_none(), "{}", c["name"]);
        let note = Note::parse(c["checkpoint"].as_str().unwrap().as_bytes()).unwrap();
        let r = &c["result"];
        match note.check(&chain, &leaves) {
            Ok(now) => {
                assert_eq!(r["ok"], true, "{}", c["name"]);
                assert_eq!(now.size, n(&r["entries"]));
                assert_eq!(now.root, hash(&r["root"]));
            }
            Err(b) => {
                assert_eq!(r["ok"], false, "{}: {b}", c["name"]);
                assert_eq!(
                    (b.seq, b.error.code.as_str()),
                    (n(&r["seq"]), r["error"].as_str().unwrap()),
                    "{}",
                    c["name"]
                );
            }
        }
    }
}
