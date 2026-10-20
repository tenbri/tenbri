//! RFC 3161 tokens from the test TSA, checked against pinned roots; no network.

use tenbri_anchor::test_tsa::TestTsa;
use tenbri_anchor::{parse_roots, verify};

const TEXT: &[u8] =
    b"tnb1:170241c12e8724974ea3b10fe536b7d8\n10\nPJ1DOrIgPq0x8PnBw1kFhcgQyqffH+G6SS74egRynLc=\n";
const AT: u64 = 1_792_500_000;

fn err(r: Result<tenbri_anchor::Timestamp, tenbri_core::Error>) -> String {
    let e = r.unwrap_err();
    assert_eq!(e.code.as_str(), "bad_timestamp");
    e.detail
}

#[test]
fn a_token_verifies_against_its_pinned_root_only() {
    let tsa = TestTsa::new(b"\x01 tenbri test tsa");
    let roots = parse_roots(tsa.root_pem().as_bytes()).unwrap();
    let tsr = tsa.respond(TEXT, AT, None);
    let ts = verify(&tsr, TEXT, &roots).unwrap();
    assert_eq!(ts.unix, AT);
    assert!(ts.tsa.contains("Tenbri Test TSA 1"), "{}", ts.tsa);
    // Deterministic, for the test vectors.
    assert_eq!(
        tsr,
        TestTsa::new(b"\x01 tenbri test tsa").respond(TEXT, AT, None)
    );

    assert!(err(verify(&tsr, b"other text", &roots)).contains("other data"));
    let other = TestTsa::new(b"\x02 another tsa");
    let other_roots = parse_roots(other.root_pem().as_bytes()).unwrap();
    assert!(err(verify(&tsr, TEXT, &other_roots)).contains("chain"));
    assert!(err(verify(&tsa.respond_changed(TEXT, AT), TEXT, &roots)).contains("changed"));
    // Before the certificates' validity.
    assert!(
        err(verify(
            &tsa.respond(TEXT, 1_700_000_000, None),
            TEXT,
            &roots
        ))
        .contains("valid")
    );
    let mut flipped = tsr.clone();
    let n = flipped.len();
    flipped[n - 3] ^= 1;
    err(verify(&flipped, TEXT, &roots));
    assert!(err(verify(b"not DER", TEXT, &roots)).contains("TimeStampResp"));
}

#[tokio::test(flavor = "current_thread")]
async fn asks_a_tsa_over_http() {
    let tsa = TestTsa::new(b"\x01 tenbri test tsa");
    let roots = parse_roots(tsa.root_pem().as_bytes()).unwrap();
    let url = tsa.serve().await.unwrap();
    let tsr = tenbri_anchor::timestamp(&url, TEXT).await.unwrap();
    verify(&tsr, TEXT, &roots).unwrap();
}

/// A response made by OpenSSL's `ts -reply` with an RSA key (tests/fixtures/README.md): the RSA
/// path, and a token Tenbri did not make.
#[test]
fn an_openssl_rsa_token_verifies() {
    let roots = parse_roots(include_bytes!("fixtures/openssl-root.pem")).unwrap();
    let tsr = include_bytes!("fixtures/openssl-rsa.tsr");
    let text = include_bytes!("fixtures/openssl-text.txt");
    verify(tsr, text, &roots).unwrap();
    err(verify(tsr, b"x", &roots));
}

/// Against a public TSA: set TENBRI_TSA_URL (and TENBRI_TSA_ROOTS, a PEM file, to check it).
#[tokio::test(flavor = "current_thread")]
async fn a_public_tsa() {
    let Ok(url) = std::env::var("TENBRI_TSA_URL") else {
        return;
    };
    let tsr = tenbri_anchor::timestamp(&url, TEXT).await.unwrap();
    if let Ok(path) = std::env::var("TENBRI_TSA_ROOTS") {
        let roots = parse_roots(&std::fs::read(path).unwrap()).unwrap();
        println!("{:?}", verify(&tsr, TEXT, &roots).unwrap());
    }
}
