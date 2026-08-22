# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-08-19

### Added
- Groth16 proof verification for BN254 curve
- snarkjs-compatible JSON format support
- CLI interface with clap argument parsing
- Test proof generator (`generate_test_proof` binary)
- Library API for programmatic verification
- Structured error types with thiserror
- Comprehensive unit and integration tests
- GitHub Actions CI pipeline
- MIT license file
- Contributing guidelines
- `verify_from_str` for JSON string verification
- `from_reader` functions for `io::Read` sources
- `parse_from_bytes` functions for byte slice input
- `verify_batch` for multiple proofs against one verification key
- `VerifyBuilder` fluent API for proof verification
- `to_json_string` methods on SnarkjsProof/SnarkjsVKey
- Getter methods: `protocol()`, `curve()`, `n_public()`
- `Display` impls for SnarkjsProof and SnarkjsVKey
- `parse_g1_unchecked` and `parse_g2_unchecked` for advanced usage
- `public_input_count` helper in verifier
- `error::code()` and `error::is_recoverable()` on VerifyError
- Type aliases: `Proof`, `VerifyingKey`, `Fr`
- `serde_json` re-export for downstream convenience
- `deny_unknown_fields` on SnarkjsProof serde
- Standalone verify example binary
- Criterion benchmarks for parse and verify workflows
- SECURITY.md vulnerability reporting policy
- FAQ section in README
- README badges for license, Rust version, and CI
- Justfile and Makefile for development workflows
- `.cargo/config.toml` with optimized release profile
- `deny.toml` for cargo-deny license and advisory checks
