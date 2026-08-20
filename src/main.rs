//! CLI entry point for the Groth16 zero-knowledge proof verifier.
//!
//! Provides a command-line interface to verify Groth16 proofs
//! against verification keys and public inputs in snarkjs JSON format.

mod parser;
mod verifier;

use clap::Parser;
use std::process;

use zkverify_rs::error::VerifyError;

/// Groth16 Zero-Knowledge Proof Verifier for BN254
#[derive(Parser, Debug)]
#[command(name = "zkverify-rs", version)]
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

fn run(args: Args) -> Result<(), VerifyError> {
    let vk = parser::load_vkey(&args.vkey)?;
    let proof = parser::load_proof(&args.proof)?;
    let public_inputs = parser::load_public(&args.inputs)?;
    verifier::verify_and_report(&vk, &proof, &public_inputs)?;

    Ok(())
}
