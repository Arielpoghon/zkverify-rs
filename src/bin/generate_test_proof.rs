use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, LinearCombination};
use ark_snark::SNARK;
use rand::thread_rng;
use std::fs;
struct MulCircuit {
    a: Option<Fr>,
    b: Option<Fr>,
    c: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for MulCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| {
            self.a.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let b = cs.new_witness_variable(|| {
            self.b.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let c = cs.new_input_variable(|| {
            self.c.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Constraint: a * b = c
        // Use LinearCombination explicitly
        let a_lc = LinearCombination::from(a);
        let b_lc = LinearCombination::from(b);
        let c_lc = LinearCombination::from(c);
        
        cs.enforce_constraint(a_lc, b_lc, c_lc)?;

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating test Groth16 proof...");

    let rng = &mut thread_rng();

    // Create a simple circuit: a * b = c where a = 3, b = 5, c = 15
    let a_val = Fr::from(3u32);
    let b_val = Fr::from(5u32);
    let c_val = a_val * b_val;

    // Setup phase - without concrete values
    let circuit = MulCircuit {
        a: None,
        b: None,
        c: None,
    };

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng)
        .map_err(|e| format!("Failed to setup: {:?}", e))?;

    println!("Setup complete");

    // Create proof with concrete values
    let circuit_with_values = MulCircuit {
        a: Some(a_val),
        b: Some(b_val),
        c: Some(c_val),
    };

    let proof = Groth16::<Bn254>::prove(&pk, circuit_with_values, rng)
        .map_err(|e| format!("Failed to create proof: {:?}", e))?;

    println!("Proof created successfully");

    let public_inputs = vec![c_val];

    // Serialize proof to snarkjs format
    let pi_a = proof.a;
    let pi_b = proof.b;
    let pi_c = proof.c;

    let proof_json = serde_json::json!({
        "pi_a": [
            pi_a.x.to_string(),
            pi_a.y.to_string(),
            "1"
        ],
        "pi_b": [
            [
                pi_b.x.c0.to_string(),
                pi_b.x.c1.to_string()
            ],
            [
                pi_b.y.c0.to_string(),
                pi_b.y.c1.to_string()
            ],
            ["1", "0"]
        ],
        "pi_c": [
            pi_c.x.to_string(),
            pi_c.y.to_string(),
            "1"
        ],
        "protocol": "groth16",
        "curve": "bn254"
    });

    // Serialize verifying key to snarkjs format
    let alpha_g1 = vk.alpha_g1;
    let beta_g2 = vk.beta_g2;
    let gamma_g2 = vk.gamma_g2;
    let delta_g2 = vk.delta_g2;

    let mut ic_json = Vec::new();
    for point in &vk.gamma_abc_g1 {
        ic_json.push(serde_json::json!([
            point.x.to_string(),
            point.y.to_string(),
            "1"
        ]));
    }

    let vkey_json = serde_json::json!({
        "protocol": "groth16",
        "curve": "bn254",
        "nPublic": public_inputs.len(),
        "vk_alpha_1": [
            alpha_g1.x.to_string(),
            alpha_g1.y.to_string(),
            "1"
        ],
        "vk_beta_2": [
            [
                beta_g2.x.c0.to_string(),
                beta_g2.x.c1.to_string()
            ],
            [
                beta_g2.y.c0.to_string(),
                beta_g2.y.c1.to_string()
            ],
            ["1", "0"]
        ],
        "vk_gamma_2": [
            [
                gamma_g2.x.c0.to_string(),
                gamma_g2.x.c1.to_string()
            ],
            [
                gamma_g2.y.c0.to_string(),
                gamma_g2.y.c1.to_string()
            ],
            ["1", "0"]
        ],
        "vk_delta_2": [
            [
                delta_g2.x.c0.to_string(),
                delta_g2.x.c1.to_string()
            ],
            [
                delta_g2.y.c0.to_string(),
                delta_g2.y.c1.to_string()
            ],
            ["1", "0"]
        ],
        "ic": ic_json
    });

    let public_json = public_inputs
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>();

    // Create examples directory if it doesn't exist
    fs::create_dir_all("examples")?;

    // Write files
    fs::write(
        "examples/proof.json",
        serde_json::to_string_pretty(&proof_json)?,
    )?;

    fs::write(
        "examples/vkey.json",
        serde_json::to_string_pretty(&vkey_json)?,
    )?;

    fs::write(
        "examples/public.json",
        serde_json::to_string_pretty(&public_json)?,
    )?;

    println!("✓ Proof files generated:");
    println!("  - examples/proof.json");
    println!("  - examples/vkey.json");
    println!("  - examples/public.json");
    println!("\nTest circuit: a * b = c, where a=3, b=5, c=15");

    Ok(())
}




// commit-cycle-96-1782725430845716584
