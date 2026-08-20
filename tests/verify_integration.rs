use zkverify_rs::parser;
use zkverify_rs::verifier;

#[test]
fn test_parse_and_verify_example_proof() {
    let vkey = parser::load_vkey("examples/vkey.json").expect("failed to load vkey");
    let proof = parser::load_proof("examples/proof.json").expect("failed to load proof");
    let public = parser::load_public("examples/public.json").expect("failed to load public");

    let result = verifier::verify_proof(&vkey, &proof, &public);
    assert!(result.is_ok(), "verification returned error: {:?}", result.err());
}

#[test]
fn test_parse_example_files_no_panic() {
    let _vkey = parser::load_vkey("examples/vkey.json").unwrap();
    let _proof = parser::load_proof("examples/proof.json").unwrap();
    let _public = parser::load_public("examples/public.json").unwrap();
}

#[test]
fn test_wrong_public_inputs_fail_verification() {
    let vkey = parser::load_vkey("examples/vkey.json").expect("failed to load vkey");
    let proof = parser::load_proof("examples/proof.json").expect("failed to load proof");

    let dir = std::env::temp_dir().join("zkverify_integration_wrong");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("public.json");
    std::fs::write(&path, r#"["999"]"#).unwrap();

    let wrong_public = parser::load_public(path.to_str().unwrap()).unwrap();
    let result = verifier::verify_proof(&vkey, &proof, &wrong_public);

    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_round_trip_generate_and_verify() {
    use std::process::Command;

    // Generate fresh proof files
    let gen_output = Command::new("cargo")
        .args(["run", "--bin", "generate_test_proof", "--release"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to run generate_test_proof");

    assert!(
        gen_output.status.success(),
        "generate_test_proof failed: {}",
        String::from_utf8_lossy(&gen_output.stderr)
    );

    // Verify the freshly generated proof
    let vkey = parser::load_vkey("examples/vkey.json").unwrap();
    let proof = parser::load_proof("examples/proof.json").unwrap();
    let public = parser::load_public("examples/public.json").unwrap();

    let result = verifier::verify_proof(&vkey, &proof, &public);
    assert!(result.is_ok(), "round-trip verification failed: {:?}", result.err());
}
