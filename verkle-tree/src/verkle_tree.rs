use std::vec::Vec;
use ark_bn254::{Fr as F, G1Affine};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::CanonicalSerialize;
use crate::kzg_commitment::KZGCommitment;

use blake3::Hasher; // ensure blake3 in Cargo.toml

use crate::VERKLE_TREE_WIDTH;

/// KZG-based multi-ary Verkle-style commitment tree (off-chain builder only for now).
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
    children: Option<Vec<VerkleNode>>, // None => leaf layer node (holds raw leaves in its poly)
    raw_leaf_count: usize,             // number of original raw leaves beneath
}

/// Single-leaf proof path (root -> leaf node).
#[derive(Debug, Clone)]
pub struct VerkleProof {
    pub leaf_index: u32,
    pub leaf_value: F,
    pub path: Vec<ProofNode>, // root-first, last entry is leaf layer node opening
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
    pub fn new(leaves: &[F]) -> Result<Self, VerkleTreeError> {
        if leaves.is_empty() {
            return Err(VerkleTreeError::EmptyInput);
        }
        let kzg = KZGCommitment::new(VERKLE_TREE_WIDTH);
        // Build leaf nodes
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
            current = Self::parent_layer(&kzg, current);
        }
        let root = current.pop().unwrap();
        Ok(Self {
            total_leaves: leaves.len(),
            root,
            kzg,
        })
    }

    fn parent_layer(kzg: &KZGCommitment, layer: Vec<VerkleNode>) -> Vec<VerkleNode> {
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
    pub fn leaf_count(&self) -> usize {
        self.total_leaves
    }

    pub fn prove(&self, leaf_index: usize, leaf_value: F) -> Result<VerkleProof, VerkleTreeError> {
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

/// Hash compressed commitment bytes to field element (domain separated).
pub fn hash_commitment_to_field(c: &G1Affine) -> F {
    let mut bytes = Vec::with_capacity(48);
    c.serialize_compressed(&mut bytes)
        .expect("serialize commitment");
    hash_to_field(b"verkle:child", &bytes)
}

/// Hash arbitrary bytes (e.g. original leaf data) to field; caller may pre-hash externally and pass result as F.
pub fn hash_leaf_bytes_to_field(data: &[u8]) -> F {
    hash_to_field(b"verkle:leaf", data)
}

fn hash_to_field(domain: &[u8], data: &[u8]) -> F {
    // 64-byte wide expansion using two Blake3 hashes with domain separation.
    let mut h1 = Hasher::new();
    h1.update(domain);
    h1.update(data);
    let r1 = h1.finalize();
    let mut h2 = Hasher::new();
    h2.update(domain);
    h2.update(data);
    h2.update(&[1]);
    let r2 = h2.finalize();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(r1.as_bytes());
    wide[32..].copy_from_slice(r2.as_bytes());
    F::from_le_bytes_mod_order(&wide)
}

/// Off-chain verification (mirrors what an on-chain verifier would do, minus no_std concerns).
pub fn verify_proof(root: &G1Affine, proof: &VerkleProof) -> bool {
    if proof.path.is_empty() {
        return false;
    }
    if proof.path[0].commitment != *root {
        return false;
    }
    // Reconstruct KZG commitment object (width constant).
    let kzg = KZGCommitment::new(VERKLE_TREE_WIDTH);
    // Iterate nodes; verify each and linkage.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_prove_small() {
        // 100 random pseudo-leaves (deterministic for test)
        let leaves: Vec<F> = (0u64..100)
            .map(|i| hash_leaf_bytes_to_field(&i.to_le_bytes()))
            .collect();
        let tree = VerkleTree::new(&leaves).unwrap();
        for idx in [0usize, 1, 31, 32, 63, 64, 99] {
            // sample indices
            let leaf_val = leaves[idx];
            let proof = tree.prove(idx, leaf_val).unwrap();
            assert!(verify_proof(&tree.root_commitment(), &proof));
        }
    }
}
