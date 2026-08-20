#![warn(missing_docs)]

//! zkverify-rs: A Groth16 zero-knowledge proof verifier for BN254.
//!
//! This crate provides tools for verifying Groth16 proofs in
//! snarkjs-compatible JSON format using the arkworks cryptography library.

pub mod error;
pub mod parser;
pub mod verifier;

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
