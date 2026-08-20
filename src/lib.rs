#![warn(missing_docs)]

//! zkverify-rs: A Groth16 zero-knowledge proof verifier for BN254.
//!
//! This crate provides tools for verifying Groth16 proofs in
//! snarkjs-compatible JSON format using the arkworks cryptography library.

pub mod error;
pub mod parser;
pub mod verifier;
