use ark_bls12_381::{Fr, G1Affine};
use ark_poly::univariate::DensePolynomial;
use kzg_commitment::KZGCommitment;

pub struct VerkleTree{
    nodes: Vec<VerkleNode>,
    kzg: KZGCommitment   
}

#[derive(Debug, Clone)]
pub struct VerkleNode{
    commitment: G1Affine,
    polynomial: DensePolynomial<Fr>,
}

#[derive(Debug, Clone)]
pub struct VerkleProof {
    pub proofs: Vec<ProofNode>,
}

#[derive(Debug, Clone)]
pub struct ProofNode {
    pub commitment: G1Affine,
    pub proof: G1Affine,
    pub point: Vec<(Fr, Fr)>,
}