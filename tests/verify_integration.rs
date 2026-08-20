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

#[test]
fn test_tampered_proof_fails_verification() {
    let vkey = parser::load_vkey("examples/vkey.json").expect("failed to load vkey");
    let proof = parser::load_proof("examples/proof.json").expect("failed to load proof");
    let public = parser::load_public("examples/public.json").expect("failed to load public");

    // Modify the proof by loading it, changing a field, and re-serializing
    let proof_json_str = std::fs::read_to_string("examples/proof.json").unwrap();
    let mut proof_json: serde_json::Value = serde_json::from_str(&proof_json_str).unwrap();

    // Tamper with pi_a x-coordinate by appending "1" to make it different
    if let Some(pi_a) = proof_json.get_mut("pi_a") {
        if let Some(arr) = pi_a.as_array_mut() {
            if let Some(first) = arr.first_mut() {
                let s = first.as_str().unwrap().to_string();
                *first = serde_json::Value::String(format!("{}1", s));
            }
        }
    }

    let dir = std::env::temp_dir().join("zkverify_tampered");
    std::fs::create_dir_all(&dir).unwrap();
    let tampered_path = dir.join("proof.json");
    std::fs::write(&tampered_path, serde_json::to_string(&proof_json).unwrap()).unwrap();

    let tampered_proof = parser::load_proof(tampered_path.to_str().unwrap());
    if let Ok(tampered) = tampered_proof {
        let result = verifier::verify_proof(&vkey, &tampered, &public);
        assert!(result.is_err(), "tampered proof should not verify");
    }

    std::fs::remove_dir_all(&dir).unwrap();
}
