pub mod airdrop_verkle_tree;
mod csv_entry;
mod error;
pub mod kzg_commitment;
mod tree_node;
mod verkle_tree;

// Re-export main types
pub use airdrop_verkle_tree::AirdropVerkleTree;
pub use csv_entry::{AirdropCategory, CsvEntry};
pub use error::VerkleTreeError;
pub use tree_node::TreeNode;
pub use verkle_tree::{verify_proof_bytes, verify_tree_node_proof, VerkleProof, VerkleTree};

// Chosen branching factor for Verkle-style KZG tree.
// Keep small to limit on-chain verification cost; 32 yields depth ~= log_32(n).
pub const VERKLE_TREE_WIDTH: usize = 32;
