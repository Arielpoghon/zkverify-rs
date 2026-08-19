use zkverify_rs::parser;
use zkverify_rs::verifier;

#[test]
fn test_parse_and_verify_example_proof() {
    let vkey = parser::load_vkey("examples/vkey.json").expect("failed to load vkey");
    let proof = parser::load_proof("examples/proof.json").expect("failed to load proof");
    let public = parser::load_public("examples/public.json").expect("failed to load public");

    let result = verifier::verify_proof(&vkey, &proof, &public);
    assert!(result.is_ok(), "verification returned error: {:?}", result.err());
    assert!(result.unwrap(), "proof should verify successfully");
}

#[test]
fn test_parse_example_files_no_panic() {
    // Verify that all example files can be parsed without panicking
    let _vkey = parser::load_vkey("examples/vkey.json").unwrap();
    let _proof = parser::load_proof("examples/proof.json").unwrap();
    let _public = parser::load_public("examples/public.json").unwrap();
}

#[test]
fn test_wrong_public_inputs_fail_verification() {
    let vkey = parser::load_vkey("examples/vkey.json").expect("failed to load vkey");
    let proof = parser::load_proof("examples/proof.json").expect("failed to load proof");

    // Use wrong public inputs (999 instead of 15)
    let dir = std::env::temp_dir().join("zkverify_integration_wrong");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("public.json");
    std::fs::write(&path, r#"["999"]"#).unwrap();

    let wrong_public = parser::load_public(path.to_str().unwrap()).unwrap();
    let result = verifier::verify_proof(&vkey, &proof, &wrong_public);

    assert!(result.is_ok());
    assert!(!result.unwrap(), "wrong inputs should fail verification");

    std::fs::remove_dir_all(&dir).unwrap();
}
