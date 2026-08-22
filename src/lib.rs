#![warn(missing_docs)]

//! zkverify-rs: A Groth16 zero-knowledge proof verifier for BN254.
//!
//! This crate provides tools for verifying Groth16 proofs in
//! snarkjs-compatible JSON format using the arkworks cryptography library.
//!
//! # Quick Start
//!
//! ```no_run
//! use zkverify_rs::verify_from_files;
//!
//! fn main() -> Result<(), zkverify_rs::error::VerifyError> {
//!     verify_from_files("vkey.json", "proof.json", "public.json")?;
//!     println!("Proof is valid!");
//!     Ok(())
//! }
//! ```

pub mod error;
pub mod parser;
pub mod verifier;

/// Re-export of serde_json for downstream convenience
pub use serde_json;

/// Type alias for a Groth16 proof on BN254
pub type Proof = ark_groth16::Proof<ark_bn254::Bn254>;

/// Type alias for a Groth16 verification key on BN254
pub type VerifyingKey = ark_groth16::VerifyingKey<ark_bn254::Bn254>;

/// Type alias for a BN254 field element (Fr)
pub type Fr = ark_bn254::Fr;

use crate::error::VerifyError;

/// Convenience function to verify a proof directly from file paths.
///
/// Loads the verification key, proof, and public inputs from the
/// given JSON file paths and verifies the proof.
///
/// # Errors
///
/// Returns [`VerifyError`] if any file cannot be read, parsed, or
/// if the proof is invalid.
///
/// # Example
///
/// ```no_run
/// use zkverify_rs::verify_from_files;
///
/// verify_from_files("vkey.json", "proof.json", "public.json")
///     .expect("proof verification failed");
/// ```
pub fn verify_from_files(
    vkey_path: &str,
    proof_path: &str,
    public_path: &str,
) -> Result<(), VerifyError> {
    let vk = parser::load_vkey(vkey_path)?;
    let proof = parser::load_proof(proof_path)?;
    let public = parser::load_public(public_path)?;
    verifier::verify_proof(&vk, &proof, &public)
}

/// Verify a proof directly from JSON strings.
///
/// Parses the verification key, proof, and public inputs from
/// raw JSON strings and verifies the proof.
///
/// # Errors
///
/// Returns [`VerifyError`] if any JSON is malformed or
/// if the proof is invalid.
pub fn verify_from_str(
    vkey_json: &str,
    proof_json: &str,
    public_json: &str,
) -> Result<(), VerifyError> {
    let vk = parser::parse_vkey_json(vkey_json)?;
    let proof = parser::parse_proof_json(proof_json)?;
    let public = parser::parse_public_json(public_json)?;
    verifier::verify_proof(&vk, &proof, &public)
}

/// Verify multiple proofs against the same verification key.
///
/// Returns `Ok(())` only if all proofs verify successfully.
/// Returns `Err` with the index of the first failing proof.
///
/// # Errors
///
/// Returns [`VerifyError`] if any proof fails verification.
pub fn verify_batch(
    vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>,
    proofs_and_inputs: &[(
        ark_groth16::Proof<ark_bn254::Bn254>,
        Vec<ark_bn254::Fr>,
    )],
) -> Result<(), VerifyError> {
    for (i, (proof, public)) in proofs_and_inputs.iter().enumerate() {
        verifier::verify_proof(vk, proof, public).map_err(|e| {
            VerifyError::Other(format!("proof at index {} failed: {}", i, e))
        })?;
    }
    Ok(())
}
