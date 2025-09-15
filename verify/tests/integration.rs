use ark_bn254::Fr as F;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use kzg::{verify_path_multiproof, SrsEval};
use verify::{verify_aggregated_with_error, AggregatedVerifyError};
use verkle_tree::{TreeNode, VerkleTree};

#[test]
fn aggregated_verifier_roundtrip() {
    // build small tree
    let nodes: Vec<TreeNode> = (0..20i32)
        .map(|i| {
            let b: u8 = i as u8;
            TreeNode {
                claimant: [b; 32],
                proof: None,
                total_unlocked_staker: (i * 10) as u64,
                total_locked_staker: (i * 5) as u64,
                total_unlocked_searcher: 0,
                total_locked_searcher: 0,
                total_unlocked_validator: 0,
                total_locked_validator: 0,
            }
        })
        .collect();
    let tree = VerkleTree::new(&nodes).unwrap();
    let target = &nodes[7];
    let hash = target.hash();
    let leaf_field = F::from_le_bytes_mod_order(&hash.as_bytes()[0..32]);
    let proof = tree.generate_proof(7, leaf_field).unwrap();
    let proof_bytes = proof.to_bytes();
    let root_bytes = tree.root_bytes();
    let mut leaf_bytes = [0u8; 32];
    leaf_field
        .serialize_compressed(&mut leaf_bytes[..])
        .unwrap();
    // debug prints removed
    // Sanity: kzg internal verifier should accept
    let srs = SrsEval::deterministic();
    assert!(verify_path_multiproof(&proof.0, &srs, leaf_field));
    if let Err(e) = verify_aggregated_with_error(&root_bytes, &proof_bytes, &leaf_bytes, &srs) {
        panic!("aggregated verifier failed: {:?}", e);
    }
}

#[test]
fn aggregated_verifier_reports_error() {
    // Construct a valid proof then corrupt one byte to ensure an error is reported (not panic)
    let nodes: Vec<TreeNode> = (0..8u64)
        .map(|i| {
            let b: u8 = i as u8;
            TreeNode {
                claimant: [b; 32],
                proof: None,
                total_unlocked_staker: i,
                total_locked_staker: 0,
                total_unlocked_searcher: 0,
                total_locked_searcher: 0,
                total_unlocked_validator: 0,
                total_locked_validator: 0,
            }
        })
        .collect();
    let tree = VerkleTree::new(&nodes).unwrap();
    let target = &nodes[3];
    let hash = target.hash();
    let leaf_field = F::from_le_bytes_mod_order(&hash.as_bytes()[0..32]);
    let proof = tree.generate_proof(3, leaf_field).unwrap();
    let mut proof_bytes = proof.to_bytes();
    // Corrupt a commitments byte (after depth byte)
    if proof_bytes.len() > 10 {
        proof_bytes[10] ^= 0x01;
    }
    let mut leaf_bytes = [0u8; 32];
    leaf_field
        .serialize_compressed(&mut leaf_bytes[..])
        .unwrap();
    let root_bytes = tree.root_bytes();
    let srs = SrsEval::deterministic();
    let err = verify_aggregated_with_error(&root_bytes, &proof_bytes, &leaf_bytes, &srs).unwrap_err();
    // We expect either ProofEncoding or Pairing depending on whether corruption still deserializes
    match err {
        AggregatedVerifyError::ProofEncoding | AggregatedVerifyError::Pairing => {}
        _ => panic!("unexpected error variant: {:?}", err),
    }
}
