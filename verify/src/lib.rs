// Binary-only verifier for aggregated path multiproof (uses std for simplicity).
extern crate alloc;
use alloc::vec::Vec;
use ark_bn254::{Fr as F, G1Affine};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kzg::{verify_path_multiproof, PathMultiproof, SrsEval};
use blake3::Hasher;

// Public API: verify a single serialized Verkle aggregated proof against root & expected leaf field value.
// root_bytes: compressed G1 root commitment (64 bytes in producer code, but we accept 48 or 64 len slice)
// proof_bytes: aggregated proof binary as defined in docs/multiproof_spec.md
// expected_leaf: 32-byte field element (raw leaf hash converted externally)
pub fn verify_aggregated(root_bytes: &[u8], proof_bytes: &[u8], expected_leaf: &[u8;32]) -> bool {
    verify_aggregated_with_error(root_bytes, proof_bytes, expected_leaf).is_ok()
}

/// More diagnostic verification returning a structured error for debugging.
pub fn verify_aggregated_with_error(root_bytes: &[u8], proof_bytes: &[u8], expected_leaf: &[u8;32]) -> Result<(), AggregatedVerifyError> {
    // Use deterministic SRS directly to avoid any subtle static init differences (should be identical).
    let srs = SrsEval::deterministic();
    // Parse root (accept either 48 or 64 bytes; handle leading slice of 48)
    // BN254 compressed G1 is 32 bytes; producer stored it in a 64-byte array (remaining zeroed)
    let root_slice = if root_bytes.len() >=32 { &root_bytes[0..32] } else { return Err(AggregatedVerifyError::RootBytes); };
    let root = G1Affine::deserialize_compressed(&mut &root_slice[..]).map_err(|_| AggregatedVerifyError::RootBytes)?;
    let proof = AggregatedProof::from_bytes(proof_bytes).ok_or(AggregatedVerifyError::ProofEncoding)?;
    if proof.commitments.is_empty() { return Err(AggregatedVerifyError::Empty); }
    if proof.commitments[0]!=root { return Err(AggregatedVerifyError::RootMismatch); }
    // Derive expected leaf field element from caller bytes
    let expected_leaf_field = F::deserialize_compressed(&mut &expected_leaf[..])
        .map_err(|_| AggregatedVerifyError::LeafBytes)?;

    // Linkage checks (internal node value consistency)
    for i in 0..proof.values.len() {
        if i < proof.values.len()-1 {
            let expected = hash_child_commitment(&proof.commitments[i+1]);
            if expected != proof.values[i] {
                return Err(AggregatedVerifyError::InternalLinkage { index: i });
            }
        } else if proof.values[i] != expected_leaf_field {
            return Err(AggregatedVerifyError::LeafValueMismatch);
        }
    }
    let path_mp = PathMultiproof { commitments: proof.commitments, indices: proof.indices, values: proof.values, d_commit: proof.d_commit, y: proof.y, h_commit: proof.h_commit, w: proof.w, sigma: proof.sigma };
    if verify_path_multiproof(&path_mp, &srs, expected_leaf_field) { Ok(()) } else { Err(AggregatedVerifyError::Pairing) }
}

#[derive(Debug)]
pub enum AggregatedVerifyError {
    RootBytes,
    ProofEncoding,
    Empty,
    RootMismatch,
    LeafBytes,
    InternalLinkage { index: usize },
    LeafValueMismatch,
    Pairing,
}

/// Debug helper (not for production): attempts to segment the proof bytes and returns slice offsets.
#[cfg(feature = "debug-segments")]
pub fn debug_segment_proof(proof_bytes: &[u8]) -> Option<alloc::vec::Vec<( &'static str, core::ops::Range<usize>)>> {
    if proof_bytes.is_empty(){return None;}
    let mut segments = alloc::vec::Vec::new();
    let mut offset=0; let depth = *proof_bytes.get(offset)? as usize; segments.push(("depth", offset..offset+1)); offset+=1;
    const G1_COMP: usize = 32;
    for i in 0..depth { if offset+G1_COMP>proof_bytes.len(){return None;} segments.push(("commitment", offset..offset+G1_COMP)); offset+=G1_COMP; if i==0 { /* root */ } }
    if offset>=proof_bytes.len(){return None;} segments.push(("indices_len", offset..offset+1)); let idx_len=*proof_bytes.get(offset)? as usize; offset+=1;
    if offset+idx_len>proof_bytes.len(){return None;} segments.push(("indices", offset..offset+idx_len)); offset+=idx_len;
    if offset>=proof_bytes.len(){return None;} segments.push(("values_len", offset..offset+1)); let val_len=*proof_bytes.get(offset)? as usize; offset+=1;
    for _ in 0..val_len { if offset+32>proof_bytes.len(){return None;} segments.push(("value", offset..offset+32)); offset+=32; }
    // remaining fixed sequence: 3 * 32 + 2 * 32 = 160 bytes
    if offset+G1_COMP>proof_bytes.len(){return None;} segments.push(("d_commit", offset..offset+G1_COMP)); offset+=G1_COMP;
    if offset+G1_COMP>proof_bytes.len(){return None;} segments.push(("h_commit", offset..offset+G1_COMP)); offset+=G1_COMP;
    if offset+G1_COMP>proof_bytes.len(){return None;} segments.push(("sigma", offset..offset+G1_COMP)); offset+=G1_COMP;
    if offset+32>proof_bytes.len(){return None;} segments.push(("y", offset..offset+32)); offset+=32;
    if offset+32>proof_bytes.len(){return None;} segments.push(("w", offset..offset+32)); offset+=32;
    if offset!=proof_bytes.len() { return None; }
    Some(segments)
}

fn hash_child_commitment(c:&G1Affine)->F {
    let mut bytes = alloc::vec::Vec::new();
    c.serialize_compressed(&mut bytes).ok(); // will be 32 bytes for BN254
    let mut h = Hasher::new(); h.update(&[1u8]); h.update(&bytes); let digest = h.finalize();
    F::from_le_bytes_mod_order(&digest.as_bytes()[0..32])
}

#[derive(Debug, Clone)]
struct AggregatedProof {
    commitments: Vec<G1Affine>,
    indices: Vec<u8>,
    values: Vec<F>,
    d_commit: G1Affine,
    h_commit: G1Affine,
    sigma: G1Affine,
    y: F,
    w: F,
}

impl AggregatedProof {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty(){return None;}
        let mut offset=0; let depth = *data.get(offset)? as usize; offset+=1;
        let mut commitments=Vec::with_capacity(depth);
        const G1_COMP: usize = 32; // BN254 compressed size
        for _ in 0..depth { if offset+G1_COMP>data.len(){return None;} let mut cur=&data[offset..offset+G1_COMP]; let c=G1Affine::deserialize_compressed(&mut cur).ok()?; commitments.push(c); offset+=G1_COMP; }
        if offset>=data.len(){return None;} let idx_len=*data.get(offset)? as usize; offset+=1; if idx_len!=depth {return None;} if offset+idx_len>data.len(){return None;} let indices=data[offset..offset+idx_len].to_vec(); offset+=idx_len;
        if offset>=data.len(){return None;} let val_len=*data.get(offset)? as usize; offset+=1; if val_len!=depth {return None;} let mut values=Vec::with_capacity(val_len);
        for _ in 0..val_len { if offset+32>data.len(){return None;} let mut cur=&data[offset..offset+32]; let v=F::deserialize_compressed(&mut cur).ok()?; values.push(v); offset+=32; }
        // d_commit, h_commit, sigma, y, w (G1 compressed = 32)
        let mut cur=&data[offset..]; let d_commit=G1Affine::deserialize_compressed(&mut cur).ok()?; let consumed=data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let h_commit=G1Affine::deserialize_compressed(&mut cur).ok()?; let consumed=data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let sigma=G1Affine::deserialize_compressed(&mut cur).ok()?; let consumed=data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let y=F::deserialize_compressed(&mut cur).ok()?; let consumed=data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let w=F::deserialize_compressed(&mut cur).ok()?; // last
        Some(Self { commitments, indices, values, d_commit, h_commit, sigma, y, w })
    }
}