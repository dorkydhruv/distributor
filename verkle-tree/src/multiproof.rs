use ark_bn254::{Fr as F, G1Affine};
use kzg::{EvalPoly, SrsEval, build_path_multiproof, PathMultiproof};

// Adapter types to bridge existing Verkle tree structure to new KZG eval multiproof.
pub struct VerkleMultiproof(pub PathMultiproof);

impl VerkleMultiproof {
    pub fn to_bytes(&self) -> Vec<u8> { // TODO: compact encoding (for now reuse existing PathMultiproof fields)
        // placeholder simple serialization: length + each commitment compressed
        let p = &self.0;
        let mut out = Vec::new();
        out.push(p.commitments.len() as u8);
        for c in &p.commitments { c.serialize_compressed(&mut out).unwrap(); }
        // indices
        out.push(p.indices.len() as u8); out.extend_from_slice(&p.indices);
        // values
        out.push(p.values.len() as u8); for v in &p.values { v.serialize_compressed(&mut out).unwrap(); }
        p.d_commit.serialize_compressed(&mut out).unwrap();
        p.sigma.serialize_compressed(&mut out).unwrap();
        p.y.serialize_compressed(&mut out).unwrap();
        out
    }
}
