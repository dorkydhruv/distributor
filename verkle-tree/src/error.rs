use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerkleTreeError {
    #[error("Verkle Tree Validation Error: {0}")]
    VerkleValidationError(String),
    #[error("Verkle Root Error")]
    VerkleRootError,
    #[error("Arithmetic Error (overflow/underflow)")]
    ArithmeticError,
    #[error("Serialization Error")]
    SerializationError,
    #[error("Empty input provided")]
    EmptyInput,
    #[error("Index out of range")]
    IndexOutOfRange,
    #[error("Proof verification failed")]
    ProofFailure,
    #[error("io Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serde Error: {0}")]
    SerdeError(#[from] serde_json::Error),
}

// Conversion from verkle_tree module's VerkleTreeError to this one
impl From<crate::verkle_tree::VerkleTreeError> for VerkleTreeError {
    fn from(err: crate::verkle_tree::VerkleTreeError) -> Self {
        match err {
            crate::verkle_tree::VerkleTreeError::EmptyInput => VerkleTreeError::EmptyInput,
            crate::verkle_tree::VerkleTreeError::IndexOutOfRange => {
                VerkleTreeError::IndexOutOfRange
            }
            crate::verkle_tree::VerkleTreeError::ProofFailure => VerkleTreeError::ProofFailure,
        }
    }
}
