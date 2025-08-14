use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerkleTreeError {
    #[error("Verkle Tree Validation Error: {0}")]
    VerkleValidationError(String),
    #[error("Verkle Root Error")]
    VerkleRootError,
    #[error("io Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serde Error: {0}")]
    SerdeError(#[from] serde_json::Error),
}
