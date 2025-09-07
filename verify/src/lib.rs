#![no_std]

use ark_bn254::{G1Affine};
use ark_ff::Zero;
use ark_ff::{Field, UniformRand};
use ark_std::One;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::CanonicalDeserialize;


/// The proof contains [[u8; 160]; N] where N is the number of leaves being proven
/// The 160 bytes are made up of:
/// - 48 bytes for the commitment
/// - 48 bytes for the kzg proof
/// - 32 bytes for the leaf value
/// - 32 bytes for the leaf index
pub fn verify<const N: usize>(root_bytes: [u8; 64], proof: [[u8; 160]; N], leaf: [u8; 32]) -> bool {
    // pass a mutable reader (slice) to the deserializer
    let mut cursor = &root_bytes[..];
    let root = match G1Affine::deserialize_compressed(&mut cursor) {
        Ok(root) => root,
        Err(_) => return false,
    };

    for i in 0..N {
        let verkle_proof = match VerkleProof::from_bytes(&proof[i]) {
            Some(vp) => vp,
            None => return false,
        };
        if verkle_proof.commitment != root {
            return false;
        }
        if !kzg_verify_proof(
            verkle_proof.commitment,
            verkle_proof.leaf_index,
            verkle_proof.leaf_value,
            verkle_proof.kzg_proof,
        ) {
            return false;
        }
    }
    true
}




fn kzg_verify_proof(
    commitment: G1Affine,
    point_x: ark_bn254::Fr,
    point_y: ark_bn254::Fr,
    proof: G1Affine,
) -> bool {
    let point_poly = lagrange_interpolation(&[(point_x, point_y)]);
    let mut vanishing_polynomial = DensePolynomial::from_coefficients_slice(&[ark_bn254::Fr::from(1)]);
    for (x, _) in [(point_x, point_y)] {
        vanishing_polynomial = &vanishing_polynomial
            * &DensePolynomial::from_coefficients_slice(&[-x, ark_bn254::Fr::from(1)]);
    }
    true
}

fn lagrange_interpolation(points: &[(ark_bn254::Fr, ark_bn254::Fr)]) -> DensePolynomial<ark_bn254::Fr> {
    let mut result: DensePolynomial<ark_bn254::Fr> = DensePolynomial::zero();
    for (index, &(x_i, y_i)) in points.into_iter().enumerate() {
        let mut term = DensePolynomial::from_coefficients_slice(&[y_i]);
        for (j, &(x_j, _)) in points.iter().enumerate() {
            if j != index {
                let scalar = (x_i - x_j).inverse().unwrap();
                let numerator = DensePolynomial::from_coefficients_slice(&[
                    -x_j * scalar,
                    ark_bn254::Fr::one() * scalar,
                ]);
                    term = &term * &numerator;
                }
            }

            result += &term;
        }
        result
   
}

struct VerkleProof {
    commitment: G1Affine,
    kzg_proof: G1Affine,
    leaf_index: ark_bn254::Fr,
    leaf_value: ark_bn254::Fr,
}

impl VerkleProof {
    fn from_bytes(bytes: &[u8; 160]) -> Option<Self> {
        let commitment = G1Affine::deserialize_compressed(&bytes[0..48]).ok()?;
        let kzg_proof = G1Affine::deserialize_compressed(&bytes[48..96]).ok()?;
        let leaf_index = ark_bn254::Fr::deserialize_compressed(&bytes[96..138]).ok()?;
        let leaf_value = ark_bn254::Fr::deserialize_compressed(&bytes[138..160]).ok()?;
        Some(Self {
            commitment,
            kzg_proof,
            leaf_index,
            leaf_value,
        })
    }
}