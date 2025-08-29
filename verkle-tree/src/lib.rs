mod csv_entry;
mod error;
mod tree_node;
pub mod verkle_tree; // make public for external builder usage

// Chosen branching factor for Verkle-style KZG tree.
// Keep small to limit on-chain verification cost; 32 yields depth ~= log_32(n).
pub const VERKLE_TREE_WIDTH: usize = 32;
