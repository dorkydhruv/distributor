use ark_bn254::Fr as F;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufReader, Write},
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
    pub verkle_root: [u8; 64],
    pub max_num_nodes: u64,
    pub max_total_claim: u64,
    pub tree_nodes: Vec<TreeNode>,
}

// Custom serialization for verkle_root since [u8; 64] doesn't implement Serialize/Deserialize
#[derive(Serialize, Deserialize)]
struct AirdropVerkleTreeSerializable {
    verkle_root: Vec<u8>,
    max_num_nodes: u64,
    max_total_claim: u64,
    tree_nodes: Vec<TreeNode>,
}

impl Serialize for AirdropVerkleTree {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serializable = AirdropVerkleTreeSerializable {
            verkle_root: self.verkle_root.to_vec(),
            max_num_nodes: self.max_num_nodes,
            max_total_claim: self.max_total_claim,
            tree_nodes: self.tree_nodes.clone(),
        };
        serializable.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AirdropVerkleTree {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let serializable = AirdropVerkleTreeSerializable::deserialize(deserializer)?;
        let mut verkle_root = [0u8; 64];
        if serializable.verkle_root.len() != 64 {
            return Err(serde::de::Error::custom("Invalid verkle_root length"));
        }
        verkle_root.copy_from_slice(&serializable.verkle_root);

        Ok(AirdropVerkleTree {
            verkle_root,
            max_num_nodes: serializable.max_num_nodes,
            max_total_claim: serializable.max_total_claim,
            tree_nodes: serializable.tree_nodes,
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

    /// Load a serialized verkle tree from file path
    pub fn new_from_file(path: &PathBuf) -> Result<Self> {
        let file = File::open(path).map_err(|e| VerkleTreeError::IoError(e))?;
        let reader = BufReader::new(file);
        let tree: AirdropVerkleTree =
            serde_json::from_reader(reader).map_err(|e| VerkleTreeError::SerdeError(e))?;

        Ok(tree)
    }

    /// Write a verkle tree to a filepath
    pub fn write_to_file(&self, path: &PathBuf) -> Result<()> {
        let serialized =
            serde_json::to_string_pretty(&self).map_err(|e| VerkleTreeError::SerdeError(e))?;
        let mut file = File::create(path).map_err(|e| VerkleTreeError::IoError(e))?;
        file.write_all(serialized.as_bytes())
            .map_err(|e| VerkleTreeError::IoError(e))?;
        Ok(())
    }

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
    use std::path::PathBuf;

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
        assert!(!proof.path.is_empty());

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
            assert!(!proof.path.is_empty(), "Proof should not be empty");
        }

        // Verify we can retrieve all proofs
        for node in &tree.tree_nodes {
            let retrieved_proof = tree.get_proof(&node.claimant).unwrap();
            assert_eq!(node.proof.as_ref().unwrap(), &retrieved_proof);
        }
    }

    #[test]
    fn test_serialize_deserialize() {
        let nodes = vec![
            create_test_node([1; 32], 100, 50),
            create_test_node([2; 32], 200, 100),
        ];

        let tree = AirdropVerkleTree::new(nodes).unwrap();
        let path = PathBuf::from("test_verkle_tree.json");

        tree.write_to_file(&path).unwrap();
        let loaded_tree = AirdropVerkleTree::new_from_file(&path).unwrap();

        assert_eq!(tree.verkle_root, loaded_tree.verkle_root);
        assert_eq!(tree.max_num_nodes, loaded_tree.max_num_nodes);
        assert_eq!(tree.max_total_claim, loaded_tree.max_total_claim);

        // Clean up
        std::fs::remove_file(&path).ok();
    }
}
