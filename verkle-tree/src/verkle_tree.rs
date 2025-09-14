// use crate::kzg_commitment::KZGCommitment; // deprecated legacy
use crate::tree_node::TreeNode;
use ark_bn254::{Fr as F, G1Affine};
use ark_ff::{PrimeField, Zero};
// use ark_poly::univariate::DensePolynomial; // legacy
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake3::Hasher;
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
use kzg::{SrsEval, EvalPoly, commit_eval, build_path_multiproof, verify_path_multiproof, PathMultiproof};

/// KZG-based multi-ary Verkle-style commitment tree
/// Leaves: raw field elements. Leaf layer groups up to WIDTH leaves into one polynomial.
/// Internal nodes: polynomial over hash(field(child_commitment))).
pub struct VerkleTree {
    root: VerkleNode,
    total_leaves: usize,
    #[allow(dead_code)]
    srs: SrsEval,
}

#[derive(Debug, Clone)]
struct VerkleNode {
    commitment: G1Affine,
    #[allow(dead_code)]
    evals: [F; VERKLE_TREE_WIDTH],
    #[allow(dead_code)]
    width: usize,
    children: Option<Vec<VerkleNode>>,
    raw_leaf_count: usize,
}

/// Aggregated proof structure wrapping KZG path multiproof
#[derive(Debug, Clone)]
pub struct VerkleProof(pub PathMultiproof);

impl PartialEq for VerkleProof { fn eq(&self, other: &Self) -> bool { // compare serialized form
    self.to_bytes() == other.to_bytes()
}}

impl VerkleProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let p = &self.0;
        // depth + commitments + indices + values + d_commit + h_commit + sigma + y + w
        let mut out = Vec::new();
        out.push(p.commitments.len() as u8);
        for c in &p.commitments { c.serialize_compressed(&mut out).unwrap(); }
        out.push(p.indices.len() as u8); out.extend_from_slice(&p.indices);
        out.push(p.values.len() as u8); for v in &p.values { v.serialize_compressed(&mut out).unwrap(); }
        p.d_commit.serialize_compressed(&mut out).unwrap();
        p.h_commit.serialize_compressed(&mut out).unwrap();
        p.sigma.serialize_compressed(&mut out).unwrap();
        p.y.serialize_compressed(&mut out).unwrap();
        p.w.serialize_compressed(&mut out).unwrap();
        out
    }
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len()<1 { return None; }
        let mut offset = 0;
        let depth = data[offset] as usize; offset+=1;
        let mut commitments = Vec::with_capacity(depth);
        for _ in 0..depth { if offset+48>data.len(){return None;} let mut cur = &data[offset..offset+48]; let c = G1Affine::deserialize_compressed(&mut cur).ok()?; commitments.push(c); offset+=48; }
        if offset>=data.len() { return None; }
        let indices_len = data[offset] as usize; offset+=1; if offset+indices_len>data.len(){return None;} let indices = data[offset..offset+indices_len].to_vec(); offset+=indices_len;
        if offset>=data.len() { return None; }
        let values_len = data[offset] as usize; offset+=1; let mut values = Vec::with_capacity(values_len);
        for _ in 0..values_len { if offset>=data.len(){return None;} let mut cur=&data[offset..]; let v = F::deserialize_compressed(&mut cur).ok()?; let consumed = data.len()-cur.len()-offset; offset+=consumed; values.push(v);}        
        let mut cur=&data[offset..]; let d_commit=G1Affine::deserialize_compressed(&mut cur).ok()?; let consumed = data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let h_commit=G1Affine::deserialize_compressed(&mut cur).ok()?; let consumed = data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let sigma=G1Affine::deserialize_compressed(&mut cur).ok()?; let consumed = data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let y=F::deserialize_compressed(&mut cur).ok()?; let consumed = data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let w=F::deserialize_compressed(&mut cur).ok()?; // last element consumes rest
        Some(VerkleProof(PathMultiproof { commitments, indices, values, d_commit, y, h_commit, w, sigma }))
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
    let srs = SrsEval::deterministic();

        let mut current: Vec<VerkleNode> = leaves
            .chunks(VERKLE_TREE_WIDTH)
            .map(|chunk| {
                let mut evals = [F::zero(); VERKLE_TREE_WIDTH];
                for (i,v) in chunk.iter().enumerate() { evals[i] = *v; }
                let poly = EvalPoly { evals };
                let com = commit_eval(&poly, &srs);
                VerkleNode { commitment: com, evals, width: chunk.len(), children: None, raw_leaf_count: chunk.len() }
            }).collect();
        while current.len() > 1 {
            current = Self::create_parent_layers(&srs, current);
        }
        let root = current.pop().unwrap();
        Ok(Self {
            total_leaves: leaves.len(),
            root,
            srs,
        })
    }

    fn create_parent_layers(srs: &SrsEval, layer: Vec<VerkleNode>) -> Vec<VerkleNode> {
        layer
            .chunks(VERKLE_TREE_WIDTH)
            .map(|group| {
                let mut evals = [F::zero(); VERKLE_TREE_WIDTH];
                for (i,c) in group.iter().enumerate() { evals[i] = field_commitment!(c.commitment); }
                let poly = EvalPoly { evals };
                let com = commit_eval(&poly, srs);
                let raw_leaf_count = group.iter().map(|c| c.raw_leaf_count).sum();
                VerkleNode {
                    commitment: com,
                    evals,
                    width: group.len(),
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

    pub fn generate_proof(&self, leaf_index: usize, leaf_value: F) -> Result<VerkleProof, VerkleTreeError> {
        if leaf_index >= self.total_leaves {
            return Err(VerkleTreeError::IndexOutOfRange);
        }
        let mut polys: Vec<EvalPoly> = Vec::new();
        let mut indices: Vec<usize> = Vec::new();
        let mut values: Vec<F> = Vec::new();
        let mut node = &self.root; let mut offset = leaf_index;
        loop { match &node.children { Some(children) => {
                // locate child
                let mut acc=0usize; let mut child_idx=0usize; let mut child_offset=offset; for (i,ch) in children.iter().enumerate(){ if offset < acc + ch.raw_leaf_count { child_idx=i; child_offset=offset-acc; break;} acc+=ch.raw_leaf_count; }
                polys.push(EvalPoly { evals: node.evals }); indices.push(child_idx); values.push(field_commitment!(children[child_idx].commitment)); node=&children[child_idx]; offset=child_offset; }
            None => { polys.push(EvalPoly { evals: node.evals }); indices.push(offset); values.push(leaf_value); break; } } }
        let mp = build_path_multiproof(&polys, &indices, &self.srs).map_err(|_| VerkleTreeError::ProofFailure)?;
        // sanity: replace values inside mp with recomputed values (builder already stored them) not needed
        Ok(VerkleProof(mp))
    }
}

/// Main proof verification logic - can be used on-chain with precompiles
pub fn verify_proof(root: &G1Affine, proof: &VerkleProof, expected_leaf_value: F) -> bool {
    let p = &proof.0;
    if p.commitments.is_empty() { return false; }
    if p.commitments[0] != *root { return false; }
    // Linkage: for i < depth-1, values[i] == hash(commitments[i+1]); last equals expected_leaf_value
    for i in 0..p.values.len() { if i < p.values.len()-1 { let exp = field_commitment!(p.commitments[i+1]); if exp != p.values[i] { return false; } } else { if p.values[i] != expected_leaf_value { return false; } } }
    let verifier_srs = SrsEval::deterministic();
    verify_path_multiproof(&proof.0, &verifier_srs, expected_leaf_value)
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
            .map(|i: i32| TreeNode {
                claimant: [i as u8; 32],
                proof: None,
                total_unlocked_staker: (i * 100) as u64,
                total_locked_staker: (i * 50) as u64,
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

            // Depth equals number of nodes on path (root + leaf layer)
            assert_eq!(proof.0.commitments.len(), 2);
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
            .map(|i: i32| TreeNode {
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
            .map(|i: i32| TreeNode {
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

    #[test]
    fn test_manual_proof_bytes_roundtrip() {
        let nodes: Vec<TreeNode> = (0..10)
            .map(|i: i32| TreeNode {
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
        let leaf_hash = nodes[3].hash();
        let leaf_value = F::from_le_bytes_mod_order(&leaf_hash.as_bytes()[0..32]);
        let proof = tree.generate_proof(3, leaf_value).unwrap();
        let bytes = proof.to_bytes();
        let parsed = VerkleProof::from_bytes(&bytes).expect("parse proof");
        assert_eq!(proof.0.commitments.len(), parsed.0.commitments.len());
        assert_eq!(proof, parsed);
    }
}
