use crate::kzg_commitment::KZGCommitment;
use crate::tree_node::TreeNode;
use ark_bn254::{Fr as F, G1Affine};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake3::Hasher;
use serde::{
    de::Error as DeError, ser::Error as SerError, Deserialize, Deserializer, Serialize, Serializer,
};
use std::vec::Vec;

const LEAF_PREFIX: &[u8] = &[0];
const INTERMEDIATE_PREFIX: &[u8] = &[1];

macro_rules! hashv {
    ($($expr:expr),*) => {{
        let mut hash = Hasher::new();
        $(
            hash.update($expr);
        )*
        hash.finalize()
    }};
}

macro_rules! field_leaf {
    ($claimant:expr, $amount_locked:expr, $amount_unlocked:expr) => {{
        // Use LEAF_PREFIX consistently with TreeNode.hash()
        let hash = hashv!(
            LEAF_PREFIX,
            $claimant.as_ref(),
            &$amount_unlocked.to_le_bytes(),
            &$amount_locked.to_le_bytes()
        );
        // Convert hash directly to field element
        F::from_le_bytes_mod_order(&hash.as_bytes()[0..32])
    }};
}

macro_rules! field_commitment {
    ($commitment:expr) => {{
        let mut bytes = Vec::with_capacity(64);
        $commitment
            .serialize_compressed(&mut bytes)
            .expect("serialize commitment");
        let hash = hashv!(INTERMEDIATE_PREFIX, &bytes);
        F::from_le_bytes_mod_order(&hash.as_bytes()[0..32])
    }};
}

use crate::VERKLE_TREE_WIDTH;

/// KZG-based multi-ary Verkle-style commitment tree
/// Leaves: raw field elements. Leaf layer groups up to WIDTH leaves into one polynomial.
/// Internal nodes: polynomial over hash(field(child_commitment))).
pub struct VerkleTree {
    root: VerkleNode,
    kzg: KZGCommitment,
    total_leaves: usize,
}

#[derive(Debug, Clone)]
struct VerkleNode {
    commitment: G1Affine,
    polynomial: DensePolynomial<F>,
    children: Option<Vec<VerkleNode>>,
    raw_leaf_count: usize,
}

/// Single-leaf proof path (root -> leaf node).
#[derive(Debug, Clone)]
pub struct VerkleProof {
    pub path: Vec<ProofEntry>,
}

// Commitment, KZG proof commitment, eval index, eval value
#[derive(Debug, Clone)]
pub struct ProofEntry {
    pub commitment: G1Affine, //48 bytes
    pub kzg_proof: G1Affine, // 48 bytes
    pub eval_index: F, // 32 bytes
    pub eval_value: F, // 32 bytes
}

impl PartialEq for VerkleProof {
    fn eq(&self, other: &Self) -> bool {
        self.path.len() == other.path.len()
            && self.path.iter().zip(other.path.iter()).all(|(a, b)| a == b)
    }
}

impl PartialEq for ProofEntry {
    fn eq(&self, other: &Self) -> bool {
        // Compare by serializing to bytes since arkworks types don't implement PartialEq consistently
        let self_commitment_bytes = {
            let mut bytes = Vec::new();
            self.commitment
                .serialize_compressed(&mut bytes)
                .unwrap_or(());
            bytes
        };
        let other_commitment_bytes = {
            let mut bytes = Vec::new();
            other
                .commitment
                .serialize_compressed(&mut bytes)
                .unwrap_or(());
            bytes
        };

        let self_kzg_bytes = {
            let mut bytes = Vec::new();
            self.kzg_proof
                .serialize_compressed(&mut bytes)
                .unwrap_or(());
            bytes
        };
        let other_kzg_bytes = {
            let mut bytes = Vec::new();
            other
                .kzg_proof
                .serialize_compressed(&mut bytes)
                .unwrap_or(());
            bytes
        };

        let self_eval_index_bytes = {
            let mut bytes = Vec::new();
            self.eval_index
                .serialize_compressed(&mut bytes)
                .unwrap_or(());
            bytes
        };
        let other_eval_index_bytes = {
            let mut bytes = Vec::new();
            other
                .eval_index
                .serialize_compressed(&mut bytes)
                .unwrap_or(());
            bytes
        };

        let self_eval_value_bytes = {
            let mut bytes = Vec::new();
            self.eval_value
                .serialize_compressed(&mut bytes)
                .unwrap_or(());
            bytes
        };
        let other_eval_value_bytes = {
            let mut bytes = Vec::new();
            other
                .eval_value
                .serialize_compressed(&mut bytes)
                .unwrap_or(());
            bytes
        };

        self_commitment_bytes == other_commitment_bytes
            && self_kzg_bytes == other_kzg_bytes
            && self_eval_index_bytes == other_eval_index_bytes
            && self_eval_value_bytes == other_eval_value_bytes
    }
}

impl Serialize for VerkleProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let path_bytes: Result<Vec<Vec<u8>>, S::Error> = self
            .path
            .iter()
            .map(|entry| {
                let mut bytes = Vec::new();
                entry
                    .commitment
                    .serialize_compressed(&mut bytes)
                    .map_err(|_| S::Error::custom("Failed to serialize commitment"))?;
                entry
                    .kzg_proof
                    .serialize_compressed(&mut bytes)
                    .map_err(|_| S::Error::custom("Failed to serialize kzg_proof"))?;
                entry
                    .eval_index
                    .serialize_compressed(&mut bytes)
                    .map_err(|_| S::Error::custom("Failed to serialize eval_index"))?;
                entry
                    .eval_value
                    .serialize_compressed(&mut bytes)
                    .map_err(|_| S::Error::custom("Failed to serialize eval_value"))?;
                Ok(bytes)
            })
            .collect();

        path_bytes?.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for VerkleProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path_bytes: Vec<Vec<u8>> = Vec::deserialize(deserializer)?;
        let mut path = Vec::new();

        for bytes in path_bytes {
            let mut cursor = &bytes[..];

            let commitment = G1Affine::deserialize_compressed(&mut cursor)
                .map_err(|_| D::Error::custom("Failed to deserialize commitment"))?;
            let kzg_proof = G1Affine::deserialize_compressed(&mut cursor)
                .map_err(|_| D::Error::custom("Failed to deserialize kzg_proof"))?;
            let eval_index = F::deserialize_compressed(&mut cursor)
                .map_err(|_| D::Error::custom("Failed to deserialize eval_index"))?;
            let eval_value = F::deserialize_compressed(&mut cursor)
                .map_err(|_| D::Error::custom("Failed to deserialize eval_value"))?;

            path.push(ProofEntry {
                commitment,
                kzg_proof,
                eval_index,
                eval_value,
            });
        }

        Ok(VerkleProof { path })
    }
}

#[derive(Debug)]
pub enum VerkleTreeError {
    EmptyInput,
    IndexOutOfRange,
    ProofFailure,
}

impl VerkleTree {
    pub fn new(nodes: &[TreeNode]) -> Result<Self, VerkleTreeError> {
        if nodes.is_empty() {
            return Err(VerkleTreeError::EmptyInput);
        }

        // Convert TreeNodes to field elements using LEAF_PREFIX approach
        let leaves: Vec<F> = nodes
            .iter()
            .map(|node| {
                // TreeNode.hash() now includes LEAF_PREFIX, convert directly to field
                let hash = node.hash();
                F::from_le_bytes_mod_order(&hash.as_bytes()[0..32])
            })
            .collect();
        if leaves.is_empty() {
            return Err(VerkleTreeError::EmptyInput);
        }
        let kzg = KZGCommitment::new(VERKLE_TREE_WIDTH);

        let mut current: Vec<VerkleNode> = leaves
            .chunks(VERKLE_TREE_WIDTH)
            .map(|chunk| {
                let chunk_vec = chunk.to_vec();
                let poly = KZGCommitment::vector_to_polynomial(&chunk_vec);
                let com = kzg.commit_polynomial(&poly);
                VerkleNode {
                    commitment: com,
                    polynomial: poly,
                    children: None,
                    raw_leaf_count: chunk_vec.len(),
                }
            })
            .collect();
        while current.len() > 1 {
            current = Self::create_parent_layers(&kzg, current);
        }
        let root = current.pop().unwrap();
        Ok(Self {
            total_leaves: leaves.len(),
            root,
            kzg,
        })
    }

    fn create_parent_layers(kzg: &KZGCommitment, layer: Vec<VerkleNode>) -> Vec<VerkleNode> {
        layer
            .chunks(VERKLE_TREE_WIDTH)
            .map(|group| {
                let child_values: Vec<F> = group
                    .iter()
                    .map(|c| field_commitment!(c.commitment))
                    .collect();
                let poly = KZGCommitment::vector_to_polynomial(&child_values);
                let com = kzg.commit_polynomial(&poly);
                let raw_leaf_count = group.iter().map(|c| c.raw_leaf_count).sum();
                VerkleNode {
                    commitment: com,
                    polynomial: poly,
                    children: Some(group.to_vec()),
                    raw_leaf_count,
                }
            })
            .collect()
    }

    pub fn root_commitment(&self) -> G1Affine {
        self.root.commitment
    }

    pub fn root_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        self.root
            .commitment
            .serialize_compressed(&mut bytes[..])
            .expect("serialize root commitment");
        bytes
    }

    pub fn leaf_count(&self) -> usize {
        self.total_leaves
    }

    pub fn generate_proof(
        &self,
        leaf_index: usize,
        leaf_value: F,
    ) -> Result<VerkleProof, VerkleTreeError> {
        if leaf_index >= self.total_leaves {
            return Err(VerkleTreeError::IndexOutOfRange);
        }
        let mut path: Vec<ProofEntry> = Vec::new();
        let mut node = &self.root;
        let mut offset = leaf_index; // remaining index within this node's subtree
        loop {
            match &node.children {
                Some(children) => {
                    // Find child containing offset
                    let mut acc = 0usize;
                    let mut child_idx = 0usize;
                    let mut child_offset = offset;
                    for (i, ch) in children.iter().enumerate() {
                        if offset < acc + ch.raw_leaf_count {
                            child_idx = i;
                            child_offset = offset - acc;
                            break;
                        }
                        acc += ch.raw_leaf_count;
                    }
                    let x = F::from(child_idx as u64);
                    let eval_value = field_commitment!(children[child_idx].commitment);
                    let proof_points = vec![(x, eval_value)];
                    let proof = self
                        .kzg
                        .generate_proof(&node.polynomial, &proof_points)
                        .map_err(|_| VerkleTreeError::ProofFailure)?;
                    path.push(ProofEntry {
                        commitment: node.commitment,
                        kzg_proof: proof,
                        eval_index: F::from(child_idx as u64),
                        eval_value,
                    });
                    node = &children[child_idx];
                    offset = child_offset; // descend
                }
                None => {
                    // Leaf layer node: open at position offset
                    let x = F::from(offset as u64);
                    let proof_points = vec![(x, leaf_value)];
                    let proof = self
                        .kzg
                        .generate_proof(&node.polynomial, &proof_points)
                        .map_err(|_| VerkleTreeError::ProofFailure)?;
                    path.push(ProofEntry {
                        commitment: node.commitment,
                        kzg_proof: proof,
                        eval_index: F::from(offset as u64),
                        eval_value: leaf_value,
                    });
                    break;
                }
            }
        }
        Ok(VerkleProof { path })
    }
}

/// Main proof verification logic - can be used on-chain with precompiles
pub fn verify_proof(root: &G1Affine, proof: &VerkleProof, expected_leaf_value: F) -> bool {
    if proof.path.is_empty() {
        return false;
    }
    if proof.path[0].commitment != *root {
        return false;
    }

    // Reconstruct KZG commitment object (width constant)
    let kzg = KZGCommitment::new(VERKLE_TREE_WIDTH);

    // Iterate nodes; verify each and linkage
    for i in 0..proof.path.len() {
        let pn = &proof.path[i];
        let pts = vec![(pn.eval_index, pn.eval_value)];
        if !kzg.verify_proof(&pn.commitment, &pts, &pn.kzg_proof) {
            return false;
        }
        if i < proof.path.len() - 1 {
            // internal linkage: eval_value should be hash(child commitment)
            let child_commit = proof.path[i + 1].commitment;
            let expected = field_commitment!(child_commit);
            if expected != pn.eval_value {
                return false;
            }
        } else {
            // last node (leaf layer) eval_value should equal provided leaf_value
            if pn.eval_value != expected_leaf_value {
                return false;
            }
        }
    }
    true
}

/// Verify proof against root commitment bytes (for on-chain use)
pub fn verify_proof_bytes(
    root_bytes: &[u8; 64],
    proof: &VerkleProof,
    expected_leaf_value: F,
) -> bool {
    // Deserialize root commitment from bytes
    let root = match G1Affine::deserialize_compressed(&root_bytes[..]) {
        Ok(root) => root,
        Err(_) => return false,
    };

    verify_proof(&root, proof, expected_leaf_value)
}

/// Verify proof for a TreeNode using separate parameters (for on-chain use)
pub fn verify_tree_node_proof(
    root_bytes: &[u8; 64],
    proof: &VerkleProof,
    claimant: &[u8; 32],
    amount_locked: u64,
    amount_unlocked: u64,
) -> bool {
    // Generate leaf field element directly from components using macro
    let expected_leaf_value = field_leaf!(claimant, amount_locked, amount_unlocked);

    // Standard proof verification
    verify_proof_bytes(root_bytes, proof, expected_leaf_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csv_entry::{AirdropCategory, CsvEntry};

    #[test]
    fn test_tree_node_integration() {
        // Create sample TreeNodes
        let mut nodes = Vec::new();
        for i in 0..50 {
            let csv_entry = CsvEntry {
                pubkey: format!("user{}", i),
                amount_unlocked: 100 + i,
                amount_locked: 50 + i,
                category: if i % 3 == 0 {
                    AirdropCategory::Staker
                } else if i % 3 == 1 {
                    AirdropCategory::Validator
                } else {
                    AirdropCategory::Searcher
                },
            };
            nodes.push(TreeNode::from(csv_entry));
        }

        // Build tree from TreeNodes
        let tree = VerkleTree::new(&nodes).unwrap();
        let root_bytes = tree.root_bytes();

        // Test proofs for various indices
        for idx in [0, 15, 31, 49] {
            let node = &nodes[idx];
            let hash = node.hash();
            let leaf_value = F::from_le_bytes_mod_order(&hash.as_bytes()[0..32]);
            let proof = tree.generate_proof(idx, leaf_value).unwrap();

            // Verify with byte-based verification (on-chain style)
            assert!(verify_proof_bytes(&root_bytes, &proof, leaf_value));
            // NEW: Verify with individual parameters (on-chain style)
            assert!(verify_tree_node_proof(
                &root_bytes,
                &proof,
                &node.claimant,
                node.amount_locked(),
                node.amount_unlocked()
            ));
        }
    }

    #[test]
    fn test_proof_linkage() {
        // Build small tree to check internal proof linkage
        let nodes: Vec<TreeNode> = (0..35)
            .map(|i| TreeNode {
                claimant: [i as u8; 32],
                proof: None,
                total_unlocked_staker: i * 100,
                total_locked_staker: i * 50,
                total_unlocked_searcher: 0,
                total_locked_searcher: 0,
                total_unlocked_validator: 0,
                total_locked_validator: 0,
            })
            .collect();

        let tree = VerkleTree::new(&nodes).unwrap();
        let root_bytes = tree.root_bytes();

        // Test edge cases: first chunk, second chunk, last node
        for idx in [0, 31, 32, 34] {
            let node = &nodes[idx];
            let hash = node.hash();
            let leaf_value = F::from_le_bytes_mod_order(&hash.as_bytes()[0..32]);
            let proof = tree.generate_proof(idx, leaf_value).unwrap();

            // Should have 2 levels: leaf chunk + root
            assert_eq!(proof.path.len(), 2);
            assert!(verify_proof_bytes(&root_bytes, &proof, leaf_value));
        }
    }

    #[test]
    fn test_empty_input() {
        let empty_nodes: Vec<TreeNode> = vec![];
        let result = VerkleTree::new(&empty_nodes);
        assert!(matches!(result, Err(VerkleTreeError::EmptyInput)));
    }

    #[test]
    fn test_out_of_range_proof() {
        let nodes: Vec<TreeNode> = (0..10)
            .map(|i| TreeNode {
                claimant: [i as u8; 32],
                proof: None,
                total_unlocked_staker: 100,
                total_locked_staker: 50,
                total_unlocked_searcher: 0,
                total_locked_searcher: 0,
                total_unlocked_validator: 0,
                total_locked_validator: 0,
            })
            .collect();

        let tree = VerkleTree::new(&nodes).unwrap();
        let hash = nodes[0].hash();
        let leaf_value = F::from_le_bytes_mod_order(&hash.as_bytes()[0..32]);

        // Try to prove index beyond range
        let result = tree.generate_proof(15, leaf_value);
        assert!(matches!(result, Err(VerkleTreeError::IndexOutOfRange)));
    }

    #[test]
    fn test_macro_field_generation() {
        let claimant = [42u8; 32];
        let amount_locked = 1000u64;
        let amount_unlocked = 500u64;

        // Test field_leaf macro
        let field1 = field_leaf!(claimant, amount_locked, amount_unlocked);
        let field2 = field_leaf!(claimant, amount_locked, amount_unlocked);
        assert_eq!(field1, field2, "field_leaf should be deterministic");

        // Test different inputs produce different outputs
        let field3 = field_leaf!(claimant, amount_locked + 1, amount_unlocked);
        assert_ne!(
            field1, field3,
            "Different inputs should produce different field elements"
        );

        // Test field_commitment macro
        let tree_node = TreeNode {
            claimant,
            proof: None,
            total_unlocked_staker: amount_unlocked,
            total_locked_staker: amount_locked,
            total_unlocked_searcher: 0,
            total_locked_searcher: 0,
            total_unlocked_validator: 0,
            total_locked_validator: 0,
        };

        let tree = VerkleTree::new(&[tree_node]).unwrap();
        let commitment = tree.root_commitment();

        let field_comm1 = field_commitment!(commitment);
        let field_comm2 = field_commitment!(commitment);
        assert_eq!(
            field_comm1, field_comm2,
            "field_commitment should be deterministic"
        );
    }

    #[test]
    fn test_root_bytes_serialization() {
        let nodes: Vec<TreeNode> = (0..10)
            .map(|i| TreeNode {
                claimant: [i as u8; 32],
                proof: None,
                total_unlocked_staker: 100,
                total_locked_staker: 50,
                total_unlocked_searcher: 0,
                total_locked_searcher: 0,
                total_unlocked_validator: 0,
                total_locked_validator: 0,
            })
            .collect();

        let tree = VerkleTree::new(&nodes).unwrap();
        let root_bytes = tree.root_bytes();

        // Should be 64 bytes (compressed G1 point)
        assert_eq!(root_bytes.len(), 64);

        // Should be able to deserialize back
        let root_reconstructed = G1Affine::deserialize_compressed(&root_bytes[..]).unwrap();
        assert_eq!(root_reconstructed, tree.root_commitment());
    }
}
