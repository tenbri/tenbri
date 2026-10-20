//! spec/vectors/receipts.json: every receipt case verifies, or fails with its code.

use serde_json::Value;

#[test]
fn receipt_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../spec/vectors/receipts.json"
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let roots = tenbri_anchor::parse_roots(doc["tsa_roots"].as_str().unwrap().as_bytes()).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for c in cases {
        let (name, want) = (&c["name"], &c["result"]);
        let r = tenbri_anchor::verify_receipt(
            c["receipt"].as_str().unwrap().as_bytes(),
            c["pin"].as_str().unwrap(),
            Some(&roots),
        );
        match r {
            Ok(v) => {
                let proves: Vec<u64> = v.receipt.proved().iter().map(|e| e.seq).collect();
                let ts: Vec<u64> = v.timestamps.unwrap().iter().map(|t| t.unix).collect();
                assert_eq!(want["proves"], serde_json::json!(proves), "{name}");
                assert_eq!(want["size"], v.receipt.checkpoint.size, "{name}");
                assert_eq!(want["timestamps"], serde_json::json!(ts), "{name}");
            }
            Err(e) => assert_eq!(want["error"], e.code.as_str(), "{name}: {e}"),
        }
    }
}
