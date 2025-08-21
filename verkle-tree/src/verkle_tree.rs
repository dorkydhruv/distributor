use std::{ collections::HashSet, vec };

use ark_bls12_381::{ Fr as F, G1Affine };
use ark_ec::AffineRepr;
use ark_poly::univariate::DensePolynomial;
use kzg_commitment::KZGCommitment;

use ark_ff::PrimeField;
use kzg_commitment::ProofError;
use num_bigint::BigUint;

use rayon::prelude::*;

use crate::VERKLE_TREE_WIDTH;

pub struct VerkleTree {
    nodes: Vec<VerkleNode>,
    kzg: KZGCommitment,
}

#[derive(Debug, Clone)]
pub struct VerkleNode {
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

impl VerkleTree {
    pub fn new(items: &[Fr], sorted_hashes: bool) -> Self {
        let kzg = KZGCommitment::new(VERKLE_TREE_WIDTH);
        if items.len() <= VERKLE_TREE_WIDTH {
            let polynomial = KZGCommitment::vector_to_polynomial(&items.to_vec());
            let commitment = kzg.commit_polynomial(&polynomial);
            return VerkleTree {
                nodes: vec![VerkleNode {
                    commitment,
                    polynomial,
                }],
                kzg,
            };
        }

        let leaf_nodes = Self::create_leaf_nodes(&kzg, items);
    }
    fn create_leaf_nodes(kzg: &KZGCommitment, datas: &[Fr]) -> Vec<VerkleNode> {
        datas
            .chunks(VERKLE_TREE_WIDTH)
            .map(|chunk| {
                let polynomial = KZGCommitment::vector_to_polynomial(&chunk.to_vec());
                let commitment = kzg.commit_polynomial(&polynomial);
                VerkleNode {
                    commitment,
                    polynomial,
                }
            })
            .collect()
    }

    fn build_tree_recursively(kzg: &KZGCommitment, nodes: &[VerkleNode]) -> VerkleNode {
        if nodes.len() == 1 {
            return nodes[0].clone();
        }
        let next_level = Self::build_from_nodes(kzg, nodes);
        Self::build_tree_recursively(kzg, &next_level)
    }

    fn build_from_nodes(kzg: &KZGCommitment, nodes: &[VerkleNode]) -> Vec<VerkleNode> {
        nodes
            .chunks(VERKLE_TREE_WIDTH)
            .map(|chunk| {
                let vector_commitment_mapping = chunk
                    .iter()
                    .map(|node| Self::map_commitment_to_field(&node.commitment))
                    .collect();
                let polynomial = KZGCommitment::vector_to_polynomial(&vector_commitment_mapping);
                let commitment = kzg.commit_polynomial(&polynomial);
                VerkleNode {
                    commitment,
                    polynomial,
                }
            })
            .collect()
    }

    fn map_commitment_to_field(g1_point: &G1Affine) -> F {
        let fq_value =
            g1_point.x().expect("its the x value") + g1_point.y().expect("its the y value");
        let fq_bigint: BigUint = fq_value.into_bigint().into();
        Fr::from_le_bytes_mod_order(&fq_bigint.to_bytes_le())
    }
}
