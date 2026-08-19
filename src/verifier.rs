//! Core Groth16 proof verification logic for BN254.
//!
//! This module provides functions to verify Groth16 zero-knowledge proofs
//! using the arkworks library. It wraps the arkworks verification API
//! with user-friendly result reporting.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey, PreparedVerifyingKey};

use crate::error::VerifyError;

/// Verify a Groth16 proof with the given verification key and public inputs.
///
/// Returns `Ok(())` on success or `Err(VerifyError::InvalidProof)` if the
/// proof does not satisfy the verification equation.
#[must_use]
pub fn verify_proof(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
) -> Result<(), VerifyError> {
    let pvk = PreparedVerifyingKey::from(vk.clone());
    Groth16::<Bn254>::verify_proof(&pvk, proof, public_inputs)
        .map_err(|_| VerifyError::InvalidProof)
        .and_then(|valid| {
            if valid {
                Ok(())
            } else {
                Err(VerifyError::InvalidProof)
            }
        })
}

/// Format output with ANSI color codes for terminal display
fn format_success(msg: &str) -> String {
    format!("\x1b[32m✓\x1b[0m {}", msg)
}

fn format_error(msg: &str) -> String {
    format!("\x1b[31m✗\x1b[0m {}", msg)
}

/// Verify and print result with formatted output
pub fn verify_and_report(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
) -> Result<(), VerifyError> {
    verify_proof(vk, proof, public_inputs)?;
    println!("{}", format_success("Proof verified successfully"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_functions() {
        let success = format_success("test");
        assert!(success.contains("✓"));
        
        let error = format_error("test");
        assert!(error.contains("✗"));
    }
}
