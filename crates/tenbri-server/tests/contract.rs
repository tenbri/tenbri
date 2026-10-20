//! tenbrid matches its checked-in contract (contract/): the gRPC code in src/proto.rs is generated
//! from contract/proto, and contract/openapi.v1.yaml is the OpenAPI document the REST routes
//! produce. Run with TENBRI_BLESS=1 to rewrite both after a deliberate change, then commit them;
//! CI's contract job then checks the change only adds (oasdiff, buf breaking).

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Compares `actual` with the file at `path`, or writes it there under TENBRI_BLESS=1.
fn check(path: &Path, actual: &str) {
    if std::env::var_os("TENBRI_BLESS").is_some() {
        std::fs::write(path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        expected == actual,
        "{} is out of date; run TENBRI_BLESS=1 cargo test -p tenbri-server --test contract and commit it",
        path.display()
    );
}

#[test]
fn grpc_code_is_generated_from_the_proto() {
    let fds = protox::compile(["tenbri/v1/tenbri.proto"], [root().join("contract/proto")]).unwrap();
    let out = std::env::temp_dir().join(format!("tenbri-proto-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    tonic_prost_build::configure()
        .build_transport(false)
        .emit_rerun_if_changed(false)
        .out_dir(&out)
        .compile_fds(fds)
        .unwrap();
    let code = std::fs::read_to_string(out.join("tenbri.v1.rs")).unwrap();
    std::fs::remove_dir_all(&out).unwrap();
    check(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/proto.rs"),
        &format!(
            "// @generated from contract/proto/tenbri/v1/tenbri.proto by tests/contract.rs. Do not edit.\n{code}"
        ),
    );
}

#[test]
fn openapi_document_matches_the_routes() {
    check(
        &root().join("contract/openapi.v1.yaml"),
        &tenbri_server::openapi_yaml(),
    );
}

/// Every `$ref` names a schema the document defines: the routes document their operations, and a
/// body type missing from `components(schemas(...))` would leave a dangling reference that
/// OpenAPI tools refuse to load.
#[test]
fn openapi_references_resolve() {
    let yaml = tenbri_server::openapi_yaml();
    let defined: Vec<&str> = yaml
        .split_once("\n  schemas:\n")
        .expect("components.schemas")
        .1
        .lines()
        .take_while(|l| l.is_empty() || l.starts_with("    "))
        .filter_map(|l| l.strip_prefix("    ")?.strip_suffix(':'))
        .filter(|n| !n.starts_with(' '))
        .collect();
    let refs: Vec<&str> = yaml
        .split("#/components/schemas/")
        .skip(1)
        .map(|r| r.split(['\'', '"', '\n']).next().unwrap())
        .collect();
    assert!(!refs.is_empty());
    for r in refs {
        assert!(
            defined.contains(&r),
            "{r} is referenced but not defined; defined: {defined:?}"
        );
    }
}
