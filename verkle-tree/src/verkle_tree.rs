use crate::kzg_commitment::KZGCommitment;
use crate::tree_node::TreeNode;
use ark_bn254::{Fr as F, G1Affine};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::vec::Vec;

use blake3::Hasher;

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
    pub leaf_index: u32,
    pub leaf_value: F,
    pub path: Vec<ProofNode>,
}

#[derive(Debug, Clone)]
pub struct ProofNode {
    pub commitment: G1Affine,
    pub eval_index: u16, // slot queried within this node's polynomial
    pub eval_value: F,   // value returned by polynomial at eval_index
    pub kzg_proof: G1Affine,
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

        // Convert TreeNodes to field elements using the same hash as Merkle
        let leaves: Vec<F> = nodes
            .iter()
            .map(|node| {
                // Use the same hash method as Merkle: node.hash() -> bytes
                let hash = node.hash();
                let hash_bytes = hash.as_bytes();
                hash_to_field(b"verkle:leaf", hash_bytes)
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
                    .map(|c| hash_commitment_to_field(&c.commitment))
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

    pub fn root_bytes(&self) -> [u8; 48] {
        let mut bytes = [0u8; 48];
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
        let mut path: Vec<ProofNode> = Vec::new();
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
                    let eval_value = hash_commitment_to_field(&children[child_idx].commitment);
                    let proof_points = vec![(x, eval_value)];
                    let proof = self
                        .kzg
                        .generate_proof(&node.polynomial, &proof_points)
                        .map_err(|_| VerkleTreeError::ProofFailure)?;
                    path.push(ProofNode {
                        commitment: node.commitment,
                        eval_index: child_idx as u16,
                        eval_value,
                        kzg_proof: proof,
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
                    path.push(ProofNode {
                        commitment: node.commitment,
                        eval_index: offset as u16,
                        eval_value: leaf_value,
                        kzg_proof: proof,
                    });
                    break;
                }
            }
        }
        Ok(VerkleProof {
            leaf_index: leaf_index as u32,
            leaf_value,
            path,
        })
    }
}

/// Core hash-to-field function with domain separation
fn hash_to_field(domain: &[u8], data: &[u8]) -> F {
    // 64-byte wide expansion using two Blake3 hashes with domain separation
    let mut h1 = Hasher::new();
    h1.update(domain);
    h1.update(data);
    let r1 = h1.finalize();
    F::from_le_bytes_mod_order(&r1.as_bytes()[0..32])
}

/// Hash compressed commitment bytes to field element (domain separated)
fn hash_commitment_to_field(c: &G1Affine) -> F {
    let mut bytes = Vec::with_capacity(48);
    c.serialize_compressed(&mut bytes)
        .expect("serialize commitment");
    hash_to_field(b"verkle:child", &bytes)
}

/// Main proof verification logic - can be used on-chain with precompiles
pub fn verify_proof(root: &G1Affine, proof: &VerkleProof) -> bool {
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
        let x = F::from(pn.eval_index as u64);
        let pts = vec![(x, pn.eval_value)];
        if !kzg.verify_proof(&pn.commitment, &pts, &pn.kzg_proof) {
            return false;
        }
        if i < proof.path.len() - 1 {
            // internal linkage: eval_value should be hash(child commitment)
            let child_commit = proof.path[i + 1].commitment;
            let expected = hash_commitment_to_field(&child_commit);
            if expected != pn.eval_value {
                return false;
            }
        } else {
            // last node (leaf layer) eval_value should equal provided leaf_value
            if pn.eval_value != proof.leaf_value {
                return false;
            }
        }
    }
    true
}

/// Verify proof against root commitment bytes (for on-chain use)
pub fn verify_proof_bytes(root_bytes: &[u8; 48], proof: &VerkleProof) -> bool {
    // Deserialize root commitment from bytes
    let root = match G1Affine::deserialize_compressed(&root_bytes[..]) {
        Ok(root) => root,
        Err(_) => return false,
    };

    verify_proof(&root, proof)
}

/// Verify proof for a TreeNode (recomputes field element from node data)
pub fn verify_tree_node_proof(root_bytes: &[u8; 48], proof: &VerkleProof, node: &TreeNode) -> bool {
    // Recompute leaf field element from TreeNode
    let hash = node.hash();
    let hash_bytes = hash.as_bytes();
    let expected_leaf_value = hash_to_field(b"verkle:leaf", hash_bytes);

    // Check that proof leaf_value matches
    if proof.leaf_value != expected_leaf_value {
        return false;
    }

    // Standard proof verification
    verify_proof_bytes(root_bytes, proof)
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
            let hash_bytes = hash.as_bytes();
            let leaf_value = hash_to_field(b"verkle:leaf", hash_bytes);
            let proof = tree.generate_proof(idx, leaf_value).unwrap();

            // Verify with byte-based verification (on-chain style)
            assert!(verify_proof_bytes(&root_bytes, &proof));

            // Verify with TreeNode-specific verification
            assert!(verify_tree_node_proof(&root_bytes, &proof, node));
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
            let hash_bytes = hash.as_bytes();
            let leaf_value = hash_to_field(b"verkle:leaf", hash_bytes);
            let proof = tree.generate_proof(idx, leaf_value).unwrap();

            // Should have 2 levels: leaf chunk + root
            assert_eq!(proof.path.len(), 2);
            assert!(verify_tree_node_proof(&root_bytes, &proof, node));
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
        let hash_bytes = hash.as_bytes();
        let leaf_value = hash_to_field(b"verkle:leaf", hash_bytes);

        // Try to prove index beyond range
        let result = tree.generate_proof(15, leaf_value);
        assert!(matches!(result, Err(VerkleTreeError::IndexOutOfRange)));
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

        // Should be 48 bytes (compressed G1 point)
        assert_eq!(root_bytes.len(), 48);

        // Should be able to deserialize back
        let root_reconstructed = G1Affine::deserialize_compressed(&root_bytes[..]).unwrap();
        assert_eq!(root_reconstructed, tree.root_commitment());
    }
}
