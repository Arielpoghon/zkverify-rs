use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <vkey.json> <proof.json> <public.json>", args[0]);
        process::exit(1);
    }

    let vkey_path = &args[1];
    let proof_path = &args[2];
    let public_path = &args[3];

    let vkey = zkverify_rs::parser::load_vkey(vkey_path).unwrap_or_else(|e| {
        eprintln!("Failed to load verification key: {}", e);
        process::exit(1);
    });

    let proof = zkverify_rs::parser::load_proof(proof_path).unwrap_or_else(|e| {
        eprintln!("Failed to load proof: {}", e);
        process::exit(1);
    });

    let public = zkverify_rs::parser::load_public(public_path).unwrap_or_else(|e| {
        eprintln!("Failed to load public inputs: {}", e);
        process::exit(1);
    });

    zkverify_rs::verifier::verify_and_report(&vkey, &proof, &public).unwrap_or_else(|e| {
        eprintln!("Verification failed: {}", e);
        process::exit(1);
    });
}
