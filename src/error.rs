//! Custom error types for zkverify-rs.
//!
//! Provides structured error handling instead of raw `String` errors.

use std::fmt;

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Failed to read a file from disk.
    #[error("failed to read file '{path}': {source}")]
    IoRead {
        path: String,
        source: std::io::Error,
    },

    /// Failed to parse JSON content.
    #[error("failed to parse JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// The proof uses an unsupported protocol.
    #[error("expected protocol 'groth16', got '{0}'")]
    WrongProtocol(String),

    /// The proof uses an unsupported curve.
    #[error("expected curve 'bn254' or 'bn128', got '{0}'")]
    WrongCurve(String),

    /// Invalid coordinate dimensions in proof or key.
    #[error("invalid coordinates: {0}")]
    InvalidCoordinates(String),

    /// A field element string could not be parsed.
    #[error("failed to parse field element from '{input}': {reason}")]
    FieldParse { input: String, reason: String },

    /// The proof is invalid (does not satisfy the verification equation).
    #[error("proof verification failed")]
    InvalidProof,

    /// A wrapper for unexpected internal errors.
    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = VerifyError::InvalidProof;
        assert_eq!(format!("{}", err), "proof verification failed");

        let err = VerifyError::WrongProtocol("plonk".to_string());
        assert!(format!("{}", err).contains("plonk"));

        let err = VerifyError::WrongCurve("bls12381".to_string());
        assert!(format!("{}", err).contains("bls12381"));

        let err = VerifyError::FieldParse {
            input: "abc".to_string(),
            reason: "invalid".to_string(),
        };
        assert!(format!("{}", err).contains("abc"));
    }
}
