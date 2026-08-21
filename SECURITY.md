# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in zkverify-rs, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email the maintainer directly with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

You should receive a response within 48 hours.

## Security Considerations

### Trusted Setup
This verifier assumes the trusted setup ceremony for Groth16 was conducted securely. A compromised setup can produce valid-looking proofs without knowledge of the witness.

### Implementation Trust
zkverify-rs depends on [arkworks](https://arkworks.rs/) for cryptographic operations. Security of the underlying field arithmetic, pairing, and proof system implementations relies on the arkworks audit status.

### Input Validation
- All JSON inputs are parsed with serde, which rejects malformed data
- Curve points are validated during parsing
- Field element bounds are enforced by arkworks

### Side-Channel Resistance
This implementation is not designed to be side-channel resistant. Do not use it to verify proofs containing secret data on shared hardware.
