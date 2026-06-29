mod parser;
mod verifier;

use clap::Parser;
use std::process;

/// Groth16 Zero-Knowledge Proof Verifier for BN254
#[derive(Parser, Debug)]
#[command(name = "zkverify-rs")]
#[command(about = "A command-line Groth16 proof verifier for BN254", long_about = None)]
struct Args {
    /// Path to the verification key (vkey.json)
    #[arg(long)]
    vkey: String,

    /// Path to the proof (proof.json)
    #[arg(long)]
    proof: String,

    /// Path to the public inputs (public.json)
    #[arg(long)]
    inputs: String,
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("{}", e);
        process::exit(1);
    }
}

fn run(args: Args) -> Result<(), String> {
    // Load verification key
    let vk = parser::load_vkey(&args.vkey)?;

    // Load proof
    let proof = parser::load_proof(&args.proof)?;

    // Load public inputs
    let public_inputs = parser::load_public(&args.inputs)?;

    // Verify the proof
    verifier::verify_and_report(&vk, &proof, &public_inputs)?;

    Ok(())
}
// commit-cycle-93-1782725430757190315
