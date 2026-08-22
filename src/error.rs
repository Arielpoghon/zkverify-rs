//! Custom error types for zkverify-rs.
//!
//! Provides structured error handling instead of raw `String` errors.

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Failed to read a file from disk.
    #[error("failed to read file '{path}': {source}")]
    IoRead {
        path: String,
        #[source]
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

impl VerifyError {
    /// Get a short machine-readable error code for this error variant.
    #[inline]
    pub fn code(&self) -> &'static str {
        match self {
            Self::IoRead { .. } => "IO_READ",
            Self::Json(_) => "JSON_PARSE",
            Self::WrongProtocol(_) => "WRONG_PROTOCOL",
            Self::WrongCurve(_) => "WRONG_CURVE",
            Self::InvalidCoordinates(_) => "INVALID_COORDS",
            Self::FieldParse { .. } => "FIELD_PARSE",
            Self::InvalidProof => "INVALID_PROOF",
            Self::Other(_) => "OTHER",
        }
    }

    /// Check if this error is recoverable (e.g. file not found vs. corrupt data).
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::IoRead { .. })
    }
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

    #[test]
    fn test_io_read_error_source_chain() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = VerifyError::IoRead {
            path: "/tmp/test.json".to_string(),
            source: io_err,
        };

        assert!(std::error::Error::source(&err).is_some());
        assert!(format!("{}", err).contains("/tmp/test.json"));
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(VerifyError::InvalidProof.code(), "INVALID_PROOF");
        assert_eq!(
            VerifyError::WrongProtocol("x".into()).code(),
            "WRONG_PROTOCOL"
        );
        assert_eq!(
            VerifyError::WrongCurve("x".into()).code(),
            "WRONG_CURVE"
        );
        assert_eq!(
            VerifyError::InvalidCoordinates("x".into()).code(),
            "INVALID_COORDS"
        );
        assert_eq!(
            VerifyError::FieldParse {
                input: "x".into(),
                reason: "y".into()
            }
            .code(),
            "FIELD_PARSE"
        );
        assert_eq!(VerifyError::Other("x".into()).code(), "OTHER");
    }

    #[test]
    fn test_is_recoverable() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "no");
        let err = VerifyError::IoRead {
            path: "/x".into(),
            source: io_err,
        };
        assert!(err.is_recoverable());
        assert!(!VerifyError::InvalidProof.is_recoverable());
    }
}
