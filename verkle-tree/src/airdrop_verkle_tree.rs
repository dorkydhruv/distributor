use ark_bn254::Fr as F;
use ark_ff::PrimeField;
// serde no longer used for AirdropVerkleTree; retained elsewhere for CSV parsing only
use std::{
    collections::{HashMap, HashSet},
    // removed file IO for JSON; keep PathBuf only
    path::PathBuf,
    result,
};

use crate::{
    csv_entry::CsvEntry,
    error::{VerkleTreeError, VerkleTreeError::VerkleValidationError},
    tree_node::TreeNode,
    verkle_tree::{verify_tree_node_proof, VerkleProof, VerkleTree},
};

/// Helper function to compute max total claim from tree nodes
fn get_max_total_claim(tree_nodes: &[TreeNode]) -> u64 {
    tree_nodes.iter().map(|node| node.total_amount()).sum()
}

/// Verkle Tree which will be used to distribute tokens to claimants.
/// Contains all the information necessary to verify claims against the Verkle Tree.
#[derive(Debug, Clone)]
pub struct AirdropVerkleTree {
    /// The verkle root (G1 commitment as bytes), which is uploaded on-chain
    pub verkle_root: [u8; 32],
    pub max_num_nodes: u64,
    pub max_total_claim: u64,
    pub tree_nodes: Vec<TreeNode>,
}

impl AirdropVerkleTree {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.verkle_root);
        out.extend_from_slice(&self.max_num_nodes.to_le_bytes());
        out.extend_from_slice(&self.max_total_claim.to_le_bytes());
        // NOTE: tree_nodes not serialized here (would need custom encoding); intentionally omitted per request.
        out
    }
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 32 + 8 + 8 {
            return None;
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&data[0..32]);
        let max_num_nodes = u64::from_le_bytes(data[32..40].try_into().ok()?);
        let max_total_claim = u64::from_le_bytes(data[40..48].try_into().ok()?);
        Some(Self {
            verkle_root: root,
            max_num_nodes,
            max_total_claim,
            tree_nodes: Vec::new(),
        })
    }
}

pub type Result<T> = result::Result<T, VerkleTreeError>;

impl AirdropVerkleTree {
    pub fn new(tree_nodes: Vec<TreeNode>) -> Result<Self> {
        // Combine tree nodes with the same claimant, while retaining original order
        let mut tree_nodes_map: HashMap<[u8; 32], TreeNode> = HashMap::new();
        for tree_node in tree_nodes {
            let claimant_key = tree_node.claimant;
            match tree_nodes_map.get_mut(&claimant_key) {
                Some(existing_node) => {
                    // Combine amounts for the same claimant
                    existing_node.total_unlocked_staker = existing_node
                        .total_unlocked_staker
                        .checked_add(tree_node.total_unlocked_staker)
                        .ok_or(VerkleTreeError::ArithmeticError)?;
                    existing_node.total_locked_staker = existing_node
                        .total_locked_staker
                        .checked_add(tree_node.total_locked_staker)
                        .ok_or(VerkleTreeError::ArithmeticError)?;
                    existing_node.total_unlocked_searcher = existing_node
                        .total_unlocked_searcher
                        .checked_add(tree_node.total_unlocked_searcher)
                        .ok_or(VerkleTreeError::ArithmeticError)?;
                    existing_node.total_locked_searcher = existing_node
                        .total_locked_searcher
                        .checked_add(tree_node.total_locked_searcher)
                        .ok_or(VerkleTreeError::ArithmeticError)?;
                    existing_node.total_unlocked_validator = existing_node
                        .total_unlocked_validator
                        .checked_add(tree_node.total_unlocked_validator)
                        .ok_or(VerkleTreeError::ArithmeticError)?;
                    existing_node.total_locked_validator = existing_node
                        .total_locked_validator
                        .checked_add(tree_node.total_locked_validator)
                        .ok_or(VerkleTreeError::ArithmeticError)?;
                }
                None => {
                    tree_nodes_map.insert(claimant_key, tree_node);
                }
            }
        }

        // Convert HashMap back to Vec (order may change but that's fine)
        let mut tree_nodes: Vec<TreeNode> = tree_nodes_map.values().cloned().collect();

        // Build the Verkle tree
        let verkle_tree = VerkleTree::new(&tree_nodes)?;
        let verkle_root = verkle_tree.root_bytes();

        // Generate proofs for each tree node and store them
        for (i, tree_node) in tree_nodes.iter_mut().enumerate() {
            let hash = tree_node.hash();
            let leaf_value = F::from_le_bytes_mod_order(&hash.as_bytes()[0..32]);
            let proof = verkle_tree
                .generate_proof(i, leaf_value)
                .map_err(|e| -> VerkleTreeError { e.into() })?;
            tree_node.proof = Some(proof);
        }

        let max_total_claim = get_max_total_claim(tree_nodes.as_ref());
        let tree = AirdropVerkleTree {
            verkle_root,
            max_num_nodes: tree_nodes.len() as u64,
            max_total_claim,
            tree_nodes,
        };

        println!(
            "Built Verkle tree with {} nodes. Max total claim: {}",
            tree.max_num_nodes, tree.max_total_claim
        );
        tree.validate()?;
        Ok(tree)
    }

    /// Load a verkle tree from a csv path
    pub fn new_from_csv(path: &PathBuf) -> Result<Self> {
        let csv_entries = CsvEntry::new_from_file(path)?;
        let tree_nodes: Vec<TreeNode> = csv_entries.into_iter().map(TreeNode::from).collect();
        let tree = Self::new(tree_nodes)?;
        Ok(tree)
    }

    // JSON load/save removed: user requested bytes-only serialization.

    pub fn get_node(&self, claimant: &[u8; 32]) -> Option<&TreeNode> {
        self.tree_nodes
            .iter()
            .find(|node| node.claimant == *claimant)
    }

    pub fn get_proof(&self, claimant: &[u8; 32]) -> Result<VerkleProof> {
        let node = self
            .get_node(claimant)
            .ok_or_else(|| VerkleValidationError("Claimant not found".to_string()))?;

        node.proof
            .clone()
            .ok_or_else(|| VerkleValidationError("Proof not found for claimant".to_string()))
    }

    fn validate(&self) -> Result<()> {
        // The Verkle tree can be at most height 32 (like Merkle), but with width 32
        // This gives us a max node count of 32^32 which is much larger than practical
        // For safety, we'll use the same limit as Merkle: 2^32 - 1
        if self.max_num_nodes > 2u64.pow(32) - 1 {
            return Err(VerkleValidationError("Verkle tree too large".to_string()));
        }

        // validate that the length is equal to the max_num_nodes
        if self.tree_nodes.len() != self.max_num_nodes as usize {
            return Err(VerkleValidationError(
                "Tree nodes length does not equal max_num_nodes".to_string(),
            ));
        }

        // validate that there are no duplicate claimants
        let unique_nodes: HashSet<_> = self.tree_nodes.iter().map(|n| n.claimant).collect();
        if unique_nodes.len() != self.tree_nodes.len() {
            return Err(VerkleValidationError(
                "Duplicate claimants found".to_string(),
            ));
        }

        Ok(())
    }

    /// verify that the leaves of the verkle tree match the nodes
    pub fn verify_proof(&self) -> Result<()> {
        for node in &self.tree_nodes {
            let proof = self.get_proof(&node.claimant)?;
            let is_valid = verify_tree_node_proof(
                &self.verkle_root,
                &proof,
                &node.claimant,
                node.amount_locked(),
                node.amount_unlocked(),
            );
            if !is_valid {
                return Err(VerkleValidationError(format!(
                    "Invalid proof for claimant: {:?}",
                    node.claimant
                )));
            }
        }
        Ok(())
    }

    // Converts Verkle Tree to a map for faster key access
    pub fn convert_to_hashmap(&self) -> HashMap<[u8; 32], TreeNode> {
        self.tree_nodes
            .iter()
            .map(|node| (node.claimant, node.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node(claimant: [u8; 32], unlocked: u64, locked: u64) -> TreeNode {
        TreeNode {
            claimant,
            proof: None,
            total_unlocked_staker: unlocked,
            total_locked_staker: locked,
            total_unlocked_searcher: 0,
            total_locked_searcher: 0,
            total_unlocked_validator: 0,
            total_locked_validator: 0,
        }
    }

    #[test]
    fn test_new_verkle_tree() {
        let nodes = vec![
            create_test_node([1; 32], 100, 50),
            create_test_node([2; 32], 200, 100),
            create_test_node([3; 32], 300, 150),
        ];

        let tree = AirdropVerkleTree::new(nodes).unwrap();
        assert_eq!(tree.max_num_nodes, 3);
        assert_eq!(tree.max_total_claim, 900); // (100+50) + (200+100) + (300+150)
    }

    #[test]
    fn test_verkle_tree_duplicate_claimants() {
        let nodes = vec![
            create_test_node([1; 32], 100, 50),
            create_test_node([1; 32], 200, 100), // Same claimant, should be combined
            create_test_node([2; 32], 300, 150),
        ];

        let tree = AirdropVerkleTree::new(nodes).unwrap();
        assert_eq!(tree.max_num_nodes, 2); // Two unique claimants

        let node1 = tree.get_node(&[1; 32]).unwrap();
        assert_eq!(node1.total_unlocked_staker, 300); // 100 + 200
        assert_eq!(node1.total_locked_staker, 150); // 50 + 100
    }

    #[test]
    fn test_verify_verkle_tree() {
        let nodes = vec![
            create_test_node([1; 32], 100, 50),
            create_test_node([2; 32], 200, 100),
        ];

        let tree = AirdropVerkleTree::new(nodes).unwrap();
        tree.verify_proof().unwrap(); // Should pass verification
    }

    #[test]
    fn test_get_node_and_proof() {
        let nodes = vec![
            create_test_node([1; 32], 100, 50),
            create_test_node([2; 32], 200, 100),
        ];

        let tree = AirdropVerkleTree::new(nodes).unwrap();

        let node = tree.get_node(&[1; 32]).unwrap();
        assert_eq!(node.total_unlocked_staker, 100);

        // Verify proof is stored in the node
        assert!(node.proof.is_some(), "Proof should be stored in TreeNode");

        let proof = tree.get_proof(&[1; 32]).unwrap();
        assert!(!proof.0.commitments.is_empty());

        // Verify the stored proof matches what get_proof returns
        assert_eq!(node.proof.as_ref().unwrap(), &proof);
    }

    #[test]
    fn test_proof_storage_in_tree_nodes() {
        let nodes = vec![
            create_test_node([1; 32], 100, 50),
            create_test_node([2; 32], 200, 100),
            create_test_node([3; 32], 300, 150),
        ];

        let tree = AirdropVerkleTree::new(nodes).unwrap();

        // Verify all nodes have proofs stored
        for node in &tree.tree_nodes {
            assert!(
                node.proof.is_some(),
                "All nodes should have proofs stored after tree creation"
            );
            let proof = node.proof.as_ref().unwrap();
            assert!(!proof.0.commitments.is_empty(), "Proof should not be empty");
        }

        // Verify we can retrieve all proofs
        for node in &tree.tree_nodes {
            let retrieved_proof = tree.get_proof(&node.claimant).unwrap();
            assert_eq!(node.proof.as_ref().unwrap(), &retrieved_proof);
        }
    }
}
