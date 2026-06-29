use ark_bn254::{Fr, Fq, G1Affine, G2Affine, Bn254};
use ark_groth16::{Proof, VerifyingKey};
use ark_ff::Zero;
use serde::{Deserialize, Serialize};
use std::fs;
use std::str::FromStr;

/// Represents a snarkjs-compatible proof JSON structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkjsProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: String,
    pub curve: String,
}

/// Represents a snarkjs-compatible verifying key JSON structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkjsVKey {
    pub protocol: String,
    pub curve: String,
    #[serde(rename = "nPublic")]
    pub n_public: u32,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    pub ic: Vec<Vec<String>>,
}

/// Parse a decimal string into a base field element Fq
fn parse_fq(s: &str) -> Result<Fq, String> {
    Fq::from_str(s).map_err(|e| format!("Failed to parse Fq from '{}': {:?}", s, e))
}

/// Parse a decimal string into a scalar field element Fr  
fn parse_fr(s: &str) -> Result<Fr, String> {
    Fr::from_str(s).map_err(|e| format!("Failed to parse Fr from '{}': {:?}", s, e))
}

/// Parse G1 affine coordinates [x, y, "1"] to G1Affine
pub fn parse_g1(coords: &[String]) -> Result<G1Affine, String> {
    if coords.len() != 3 {
        return Err(format!(
            "G1 coordinates must have 3 elements, got {}",
            coords.len()
        ));
    }

    let x = parse_fq(&coords[0])?;
    let y = parse_fq(&coords[1])?;
    let z = parse_fq(&coords[2])?;

    // If z == 0, return point at infinity
    if z.is_zero() {
        return Ok(G1Affine::identity());
    }

    // Construct affine point directly
    Ok(G1Affine::new_unchecked(x, y))
}

/// Parse G2 affine coordinates [[x0,x1],[y0,y1],["1","0"]] to G2Affine
pub fn parse_g2(coords: &[Vec<String>]) -> Result<G2Affine, String> {
    if coords.len() != 3 {
        return Err(format!(
            "G2 coordinates must have 3 elements, got {}",
            coords.len()
        ));
    }

    if coords[0].len() != 2 || coords[1].len() != 2 || coords[2].len() != 2 {
        return Err("G2 coordinates must each have 2 elements (for extension field)".to_string());
    }

    // Parse X coordinate (quadratic extension field element)
    let x0 = parse_fq(&coords[0][0])?;
    let x1 = parse_fq(&coords[0][1])?;
    let x = ark_bn254::Fq2::new(x0, x1);

    // Parse Y coordinate
    let y0 = parse_fq(&coords[1][0])?;
    let y1 = parse_fq(&coords[1][1])?;
    let y = ark_bn254::Fq2::new(y0, y1);

    // Parse Z coordinate
    let z0 = parse_fq(&coords[2][0])?;
    let z1 = parse_fq(&coords[2][1])?;
    let z = ark_bn254::Fq2::new(z0, z1);

    // If z == 0, return point at infinity
    if z.is_zero() {
        return Ok(G2Affine::identity());
    }

    Ok(G2Affine::new_unchecked(x, y))
}

/// Load and parse a proof from a JSON file
pub fn load_proof(path: &str) -> Result<Proof<Bn254>, String> {
    let file_content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read proof file '{}': {}", path, e))?;

    let proof_json: SnarkjsProof = serde_json::from_str(&file_content)
        .map_err(|e| format!("Failed to parse proof JSON: {}", e))?;

    if proof_json.protocol != "groth16" {
        return Err(format!(
            "Expected protocol 'groth16', got '{}'",
            proof_json.protocol
        ));
    }

    if proof_json.curve != "bn254" && proof_json.curve != "bn128" {
        return Err(format!(
            "Expected curve 'bn254' or 'bn128', got '{}'",
            proof_json.curve
        ));
    }

    let pi_a = parse_g1(&proof_json.pi_a)?;
    let pi_b = parse_g2(&proof_json.pi_b)?;
    let pi_c = parse_g1(&proof_json.pi_c)?;

    Ok(Proof { a: pi_a, b: pi_b, c: pi_c })
}

/// Load and parse a verifying key from a JSON file
pub fn load_vkey(path: &str) -> Result<VerifyingKey<Bn254>, String> {
    let file_content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read vkey file '{}': {}", path, e))?;

    let vkey_json: SnarkjsVKey = serde_json::from_str(&file_content)
        .map_err(|e| format!("Failed to parse vkey JSON: {}", e))?;

    if vkey_json.protocol != "groth16" {
        return Err(format!(
            "Expected protocol 'groth16', got '{}'",
            vkey_json.protocol
        ));
    }

    if vkey_json.curve != "bn254" && vkey_json.curve != "bn128" {
        return Err(format!(
            "Expected curve 'bn254' or 'bn128', got '{}'",
            vkey_json.curve
        ));
    }

    let alpha_g1 = parse_g1(&vkey_json.vk_alpha_1)?;
    let beta_g2 = parse_g2(&vkey_json.vk_beta_2)?;
    let gamma_g2 = parse_g2(&vkey_json.vk_gamma_2)?;
    let delta_g2 = parse_g2(&vkey_json.vk_delta_2)?;

    let mut gamma_abc_g1 = Vec::new();
    for ic_coords in &vkey_json.ic {
        gamma_abc_g1.push(parse_g1(ic_coords)?);
    }

    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

/// Load and parse public inputs from a JSON file
pub fn load_public(path: &str) -> Result<Vec<Fr>, String> {
    let file_content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read public inputs file '{}': {}", path, e))?;

    let public_json: Vec<String> = serde_json::from_str(&file_content)
        .map_err(|e| format!("Failed to parse public inputs JSON: {}", e))?;

    let mut public_inputs = Vec::new();
    for input_str in public_json {
        let input = parse_fr(&input_str)?;
        public_inputs.push(input);
    }

    Ok(public_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_fr() {
        let fr_str = "42";
        let result = parse_fr(fr_str);
        assert!(result.is_ok());
    }
}
// commit-cycle-99-1782725430933882253
