use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, VerifyingKey, PreparedVerifyingKey};

/// Verify a Groth16 proof with the given verification key and public inputs
pub fn verify_proof(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
) -> Result<bool, String> {
    let pvk = PreparedVerifyingKey::from(vk.clone());
    Groth16::<Bn254>::verify_proof(&pvk, proof, public_inputs)
        .map_err(|e| format!("Verification failed: {:?}", e))
}

/// Format output with ANSI color codes for terminal display
fn format_success(msg: &str) -> String {
    format!("\x1b[32m✓\x1b[0m {}", msg) // Green checkmark
}

fn format_error(msg: &str) -> String {
    format!("\x1b[31m✗\x1b[0m {}", msg) // Red X
}

/// Verify and print result with formatted output
pub fn verify_and_report(
    vk: &VerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
) -> Result<(), String> {
    match verify_proof(vk, proof, public_inputs)? {
        true => {
            println!("{}", format_success("Proof verified successfully"));
            Ok(())
        }
        false => Err(format_error("Proof verification failed")),
    }
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
// commit-cycle-94-1782725430783409806
