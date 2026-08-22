//! JSON parsing and snarkjs format conversion for Groth16 proofs.
//!
//! This module handles loading and converting snarkjs-compatible JSON files
//! into arkworks-native types for the BN254 curve. It supports:
//! - Parsing verification keys (`vkey.json`)
//! - Parsing proofs (`proof.json`)
//! - Parsing public inputs (`public.json`)
//!
//! All coordinate conversions handle projective-to-affine transformation
//! and correctly identify points at infinity.

use ark_bn254::{Fr, Fq, G1Affine, G2Affine, Bn254};
use ark_groth16::{Proof, VerifyingKey};
use ark_ff::Zero;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::Read;
use std::str::FromStr;

use crate::error::VerifyError;

/// Represents a snarkjs-compatible proof JSON structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnarkjsProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: String,
    pub curve: String,
}

impl SnarkjsProof {
    /// Serialize the proof to a pretty-printed JSON string
    pub fn to_json_string(&self) -> Result<String, VerifyError> {
        serde_json::to_string_pretty(self).map_err(VerifyError::Json)
    }

    /// Get the proof protocol identifier
    #[inline]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Get the curve identifier
    #[inline]
    pub fn curve(&self) -> &str {
        &self.curve
    }
}

impl fmt::Display for SnarkjsProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SnarkjsProof(protocol={}, curve={}, pi_a=[..], pi_b=[..], pi_c=[..])",
            self.protocol, self.curve
        )
    }
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

impl SnarkjsVKey {
    /// Serialize the verifying key to a pretty-printed JSON string
    pub fn to_json_string(&self) -> Result<String, VerifyError> {
        serde_json::to_string_pretty(self).map_err(VerifyError::Json)
    }

    /// Get the verification key protocol identifier
    #[inline]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Get the curve identifier
    #[inline]
    pub fn curve(&self) -> &str {
        &self.curve
    }

    /// Get the number of public inputs
    #[inline]
    pub fn n_public(&self) -> u32 {
        self.n_public
    }
}

impl fmt::Display for SnarkjsVKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SnarkjsVKey(protocol={}, curve={}, nPublic={})",
            self.protocol, self.curve, self.n_public
        )
    }
}

/// Parse a decimal string into a base field element Fq
#[inline]
fn parse_fq(s: &str) -> Result<Fq, VerifyError> {
    Fq::from_str(s).map_err(|e| VerifyError::FieldParse {
        input: s.to_string(),
        reason: format!("{:?}", e),
    })
}

/// Parse a decimal string into a scalar field element Fr  
#[inline]
fn parse_fr(s: &str) -> Result<Fr, VerifyError> {
    Fr::from_str(s).map_err(|e| VerifyError::FieldParse {
        input: s.to_string(),
        reason: format!("{:?}", e),
    })
}

/// Parse G1 affine coordinates [x, y, "1"] to G1Affine
pub(crate) fn parse_g1(coords: &[String]) -> Result<G1Affine, VerifyError> {
    if coords.len() != 3 {
        return Err(VerifyError::InvalidCoordinates(format!(
            "G1 coordinates must have 3 elements, got {}",
            coords.len()
        )));
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

/// Parse G1 coordinates without validation (advanced usage).
///
/// # Safety
///
/// Does not validate coordinate dimensions. Caller must ensure
/// `coords` has exactly 3 elements.
pub fn parse_g1_unchecked(coords: &[String]) -> Result<G1Affine, VerifyError> {
    let x = parse_fq(&coords[0])?;
    let y = parse_fq(&coords[1])?;
    let z = parse_fq(&coords[2])?;

    if z.is_zero() {
        return Ok(G1Affine::identity());
    }

    Ok(G1Affine::new_unchecked(x, y))
}

/// Parse G2 affine coordinates [[x0,x1],[y0,y1],["1","0"]] to G2Affine
pub(crate) fn parse_g2(coords: &[Vec<String>]) -> Result<G2Affine, VerifyError> {
    if coords.len() != 3 {
        return Err(VerifyError::InvalidCoordinates(format!(
            "G2 coordinates must have 3 elements, got {}",
            coords.len()
        )));
    }

    if coords[0].len() != 2 || coords[1].len() != 2 || coords[2].len() != 2 {
        return Err(VerifyError::InvalidCoordinates(
            "G2 coordinates must each have 2 elements (for extension field)".to_string(),
        ));
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
#[must_use = "the loaded proof should be used for verification"]
pub fn load_proof(path: &str) -> Result<Proof<Bn254>, VerifyError> {
    let file_content = fs::read_to_string(path).map_err(|e| VerifyError::IoRead {
        path: path.to_string(),
        source: e,
    })?;

    let proof_json: SnarkjsProof = serde_json::from_str(&file_content)?;

    if proof_json.protocol != "groth16" {
        return Err(VerifyError::WrongProtocol(proof_json.protocol));
    }

    if proof_json.curve != "bn254" && proof_json.curve != "bn128" {
        return Err(VerifyError::WrongCurve(proof_json.curve));
    }

    let pi_a = parse_g1(&proof_json.pi_a)?;
    let pi_b = parse_g2(&proof_json.pi_b)?;
    let pi_c = parse_g1(&proof_json.pi_c)?;

    Ok(Proof { a: pi_a, b: pi_b, c: pi_c })
}

/// Load and parse a proof from any reader
pub fn load_proof_from_reader<R: Read>(reader: &mut R) -> Result<Proof<Bn254>, VerifyError> {
    let mut content = String::new();
    reader.read_to_string(&mut content).map_err(|e| VerifyError::IoRead {
        path: "<reader>".to_string(),
        source: e,
    })?;
    parse_proof_json(&content)
}

/// Load and parse a verifying key from any reader
pub fn load_vkey_from_reader<R: Read>(reader: &mut R) -> Result<VerifyingKey<Bn254>, VerifyError> {
    let mut content = String::new();
    reader.read_to_string(&mut content).map_err(|e| VerifyError::IoRead {
        path: "<reader>".to_string(),
        source: e,
    })?;
    parse_vkey_json(&content)
}

/// Load and parse public inputs from any reader
pub fn load_public_from_reader<R: Read>(reader: &mut R) -> Result<Vec<Fr>, VerifyError> {
    let mut content = String::new();
    reader.read_to_string(&mut content).map_err(|e| VerifyError::IoRead {
        path: "<reader>".to_string(),
        source: e,
    })?;
    parse_public_json(&content)
}

/// Load and parse a verifying key from a JSON file
#[must_use = "the loaded verifying key should be used for verification"]
pub fn load_vkey(path: &str) -> Result<VerifyingKey<Bn254>, VerifyError> {
    let file_content = fs::read_to_string(path).map_err(|e| VerifyError::IoRead {
        path: path.to_string(),
        source: e,
    })?;

    let vkey_json: SnarkjsVKey = serde_json::from_str(&file_content)?;

    if vkey_json.protocol != "groth16" {
        return Err(VerifyError::WrongProtocol(vkey_json.protocol));
    }

    if vkey_json.curve != "bn254" && vkey_json.curve != "bn128" {
        return Err(VerifyError::WrongCurve(vkey_json.curve));
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
#[must_use = "the loaded public inputs should be used for verification"]
pub fn load_public(path: &str) -> Result<Vec<Fr>, VerifyError> {
    let file_content = fs::read_to_string(path).map_err(|e| VerifyError::IoRead {
        path: path.to_string(),
        source: e,
    })?;

    parse_public_json(&file_content)
}

/// Parse a proof from a JSON string
pub fn parse_proof_json(json: &str) -> Result<Proof<Bn254>, VerifyError> {
    let proof_json: SnarkjsProof = serde_json::from_str(json)?;

    if proof_json.protocol != "groth16" {
        return Err(VerifyError::WrongProtocol(proof_json.protocol));
    }

    if proof_json.curve != "bn254" && proof_json.curve != "bn128" {
        return Err(VerifyError::WrongCurve(proof_json.curve));
    }

    let pi_a = parse_g1(&proof_json.pi_a)?;
    let pi_b = parse_g2(&proof_json.pi_b)?;
    let pi_c = parse_g1(&proof_json.pi_c)?;

    Ok(Proof { a: pi_a, b: pi_b, c: pi_c })
}

/// Parse a verifying key from a JSON string
pub fn parse_vkey_json(json: &str) -> Result<VerifyingKey<Bn254>, VerifyError> {
    let vkey_json: SnarkjsVKey = serde_json::from_str(json)?;

    if vkey_json.protocol != "groth16" {
        return Err(VerifyError::WrongProtocol(vkey_json.protocol));
    }

    if vkey_json.curve != "bn254" && vkey_json.curve != "bn128" {
        return Err(VerifyError::WrongCurve(vkey_json.curve));
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

/// Parse public inputs from a JSON string
pub fn parse_public_json(json: &str) -> Result<Vec<Fr>, VerifyError> {
    let public_json: Vec<String> = serde_json::from_str(json)?;

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

    #[test]
    fn test_parse_fq_valid() {
        assert!(parse_fq("0").is_ok());
        assert!(parse_fq("1").is_ok());
        assert!(parse_fq("42").is_ok());
    }

    #[test]
    fn test_parse_fq_large_value() {
        let result = parse_fq("21888242871839275222246405745257275088548364400416034343698204186575808495616");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_fq_invalid() {
        assert!(parse_fq("not_a_number").is_err());
        assert!(parse_fq("").is_err());
    }

    #[test]
    fn test_parse_g1_valid() {
        let coords = vec!["1".to_string(), "2".to_string(), "1".to_string()];
        assert!(parse_g1(&coords).is_ok());
    }

    #[test]
    fn test_parse_g1_wrong_length() {
        let coords = vec!["1".to_string(), "2".to_string()];
        let result = parse_g1(&coords);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_g1_point_at_infinity() {
        let coords = vec!["0".to_string(), "0".to_string(), "0".to_string()];
        let result = parse_g1(&coords);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_g1_unchecked_valid() {
        let coords = vec!["1".to_string(), "2".to_string(), "1".to_string()];
        assert!(parse_g1_unchecked(&coords).is_ok());
    }

    #[test]
    fn test_parse_g1_unchecked_infinity() {
        let coords = vec!["0".to_string(), "0".to_string(), "0".to_string()];
        let result = parse_g1_unchecked(&coords);
        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_to_json_string_round_trip() {
        let json = std::fs::read_to_string("examples/proof.json").unwrap();
        let proof = parse_proof_json(&json).unwrap();
        let output = proof.to_json_string().unwrap();
        let reparsed: SnarkjsProof = serde_json::from_str(&output).unwrap();
        assert_eq!(reparsed.protocol, proof.protocol);
        assert_eq!(reparsed.curve, proof.curve);
    }

    #[test]
    fn test_snarkjs_proof_display() {
        let json = std::fs::read_to_string("examples/proof.json").unwrap();
        let proof = parse_proof_json(&json).unwrap();
        let display = format!("{}", proof);
        assert!(display.contains("SnarkjsProof"));
        assert!(display.contains("groth16"));
        assert!(display.contains("bn254"));
    }

    #[test]
    fn test_snarkjs_vkey_display() {
        let json = std::fs::read_to_string("examples/vkey.json").unwrap();
        let vkey = serde_json::from_str::<SnarkjsVKey>(&json).unwrap();
        let display = format!("{}", vkey);
        assert!(display.contains("SnarkjsVKey"));
        assert!(display.contains("groth16"));
    }

    #[test]
    fn test_parse_g2_valid() {
        let coords = vec![
            vec!["1".to_string(), "2".to_string()],
            vec!["3".to_string(), "4".to_string()],
            vec!["1".to_string(), "0".to_string()],
        ];
        assert!(parse_g2(&coords).is_ok());
    }

    #[test]
    fn test_parse_g2_wrong_outer_length() {
        let coords = vec![
            vec!["1".to_string(), "2".to_string()],
            vec!["3".to_string(), "4".to_string()],
        ];
        let result = parse_g2(&coords);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_g2_wrong_inner_length() {
        let coords = vec![
            vec!["1".to_string()],
            vec!["3".to_string(), "4".to_string()],
            vec!["1".to_string(), "0".to_string()],
        ];
        let result = parse_g2(&coords);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_g2_point_at_infinity() {
        let coords = vec![
            vec!["0".to_string(), "0".to_string()],
            vec!["0".to_string(), "0".to_string()],
            vec!["0".to_string(), "0".to_string()],
        ];
        assert!(parse_g2(&coords).is_ok());
    }

    #[test]
    fn test_load_proof_missing_file() {
        let result = load_proof("nonexistent.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_proof_invalid_json() {
        let dir = std::env::temp_dir().join("zkverify_test_invalid_proof");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proof.json");
        std::fs::write(&path, "not json").unwrap();

        let result = load_proof(path.to_str().unwrap());
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_proof_wrong_protocol() {
        let dir = std::env::temp_dir().join("zkverify_test_wrong_proto");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proof.json");
        let json = r#"{"pi_a":["1","2","1"],"pi_b":[["1","2"],["3","4"],["1","0"]],"pi_c":["1","2","1"],"protocol":"plonk","curve":"bn254"}"#;
        std::fs::write(&path, json).unwrap();

        let result = load_proof(path.to_str().unwrap());
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_proof_wrong_curve() {
        let dir = std::env::temp_dir().join("zkverify_test_wrong_curve");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("proof.json");
        let json = r#"{"pi_a":["1","2","1"],"pi_b":[["1","2"],["3","4"],["1","0"]],"pi_c":["1","2","1"],"protocol":"groth16","curve":"bls12381"}"#;
        std::fs::write(&path, json).unwrap();

        let result = load_proof(path.to_str().unwrap());
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_vkey_missing_file() {
        let result = load_vkey("nonexistent.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_vkey_invalid_json() {
        let dir = std::env::temp_dir().join("zkverify_test_invalid_vkey");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vkey.json");
        std::fs::write(&path, "not json at all").unwrap();

        let result = load_vkey(path.to_str().unwrap());
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_vkey_wrong_protocol() {
        let dir = std::env::temp_dir().join("zkverify_test_vkey_wrong_proto");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vkey.json");
        let json = r#"{"protocol":"plonk","curve":"bn254","nPublic":1,"vk_alpha_1":["1","2","1"],"vk_beta_2":[["1","2"],["3","4"],["1","0"]],"vk_gamma_2":[["1","2"],["3","4"],["1","0"]],"vk_delta_2":[["1","2"],["3","4"],["1","0"]],"ic":[["1","2","1"]]}"#;
        std::fs::write(&path, json).unwrap();

        let result = load_vkey(path.to_str().unwrap());
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_public_missing_file() {
        let result = load_public("nonexistent.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_public_invalid_json() {
        let dir = std::env::temp_dir().join("zkverify_test_invalid_pub");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("public.json");
        std::fs::write(&path, "not json").unwrap();

        let result = load_public(path.to_str().unwrap());
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_public_valid() {
        let dir = std::env::temp_dir().join("zkverify_test_valid_pub");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("public.json");
        std::fs::write(&path, r#"["42","100"]"#).unwrap();

        let result = load_public(path.to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_public_empty_array() {
        let dir = std::env::temp_dir().join("zkverify_test_empty_pub");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("public.json");
        std::fs::write(&path, r#"[]"#).unwrap();

        let result = load_public(path.to_str().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_public_non_numeric() {
        let dir = std::env::temp_dir().join("zkverify_test_non_numeric_pub");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("public.json");
        std::fs::write(&path, r#"["not_a_number"]"#).unwrap();

        let result = load_public(path.to_str().unwrap());
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
