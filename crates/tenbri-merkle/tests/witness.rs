//! spec/vectors/witness.json (Experimental: witnesses).
#![cfg(feature = "witness")]

use serde_json::Value as J;
use tenbri_core::sign::decode_key;
use tenbri_merkle::Note;
use tenbri_merkle::checkpoint::unbase64;
use tenbri_merkle::witness::{Witness, cosignatures, log_vkey, parse_request};

fn load() -> J {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/witness.json"
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn keys() {
    for k in load()["keys"].as_array().unwrap() {
        let public = decode_key(k["pub"].as_str().unwrap()).unwrap();
        let vkey = k["vkey"].as_str().unwrap();
        match k["role"].as_str().unwrap() {
            "checkpoint" => assert_eq!(log_vkey(k["origin"].as_str().unwrap(), &public), vkey),
            _ => assert_eq!(Witness::parse(vkey).unwrap().key, public),
        }
    }
    // A public witness's published key (witness.glasklar.is): the same key ID derivation.
    let w =
        Witness::parse("witness.glasklar.is+90ad80e6+BLIQbbkGXsl/JeCcGIOSFnUabibY7YtB5IWlY9PRSYU2");
    assert_eq!(w.unwrap().key_id(), "90ad80e6");
}

#[test]
fn cosignature_cases() {
    for c in load()["cosignatures"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let note = Note::parse(c["note"].as_str().unwrap().as_bytes()).unwrap();
        let ws: Vec<Witness> = c["witnesses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Witness::parse(v.as_str().unwrap()).unwrap())
            .collect();
        let got = cosignatures(&note, &ws, c["need"].as_u64().unwrap() as usize);
        match (&c["result"]["ok"], got) {
            (J::Array(want), Ok(got)) => {
                let got: Vec<(String, u64)> = got.into_iter().map(|c| (c.name, c.time)).collect();
                let want: Vec<(String, u64)> = want
                    .iter()
                    .map(|c| {
                        (
                            c["name"].as_str().unwrap().into(),
                            c["time"].as_u64().unwrap(),
                        )
                    })
                    .collect();
                assert_eq!(got, want, "{name}");
            }
            (J::Null, Err(e)) => assert_eq!(e.code.as_str(), c["result"]["error"], "{name}"),
            (_, got) => panic!("{name}: {got:?}"),
        }
    }
}

#[test]
fn requests() {
    for r in load()["requests"].as_array().unwrap() {
        let (old, proof, note) = parse_request(r["body"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(old, r["old"].as_u64().unwrap());
        let want: Vec<Vec<u8>> = r["proof"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| unbase64(h.as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(proof.iter().map(|h| h.to_vec()).collect::<Vec<_>>(), want);
        assert!(Note::parse(note).is_ok());
    }
}
