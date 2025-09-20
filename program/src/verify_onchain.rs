//! Minimal on-chain aggregated path multiproof parser & verifier.
//! Reuses WIDTH=32 assumptions and compressed BN254 G1 (32 bytes) & F (32 bytes) encodings.

use alloc::vec::Vec;
use ark_bn254::{Fr as F, G1Affine};
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use kzg::{verify_path_multiproof, PathMultiproof, SrsEval};

#[derive(Debug)]
pub enum OnchainVerifyError {
    Encoding,
    RootMismatch,
    Empty,
}

pub struct AggregatedProof<'a> {
    pub raw: PathMultiproof,
    pub depth: usize,
    pub bytes: &'a [u8],
}

impl<'a> AggregatedProof<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.is_empty() { return None; }
        let mut offset = 0;
        let depth = *data.get(offset)? as usize; offset+=1;
        if depth == 0 { return None; }
        let mut commitments=Vec::with_capacity(depth);
        for _ in 0..depth { if offset+32>data.len(){return None;} let mut cur=&data[offset..offset+32]; let c=G1Affine::deserialize_compressed(&mut cur).ok()?; commitments.push(c); offset+=32; }
        if offset>=data.len(){return None;}
        let idx_len=*data.get(offset)? as usize; offset+=1; if idx_len!=depth { return None; }
        if offset+idx_len>data.len(){return None;} let indices=data[offset..offset+idx_len].to_vec(); offset+=idx_len;
        if offset>=data.len(){return None;} let val_len=*data.get(offset)? as usize; offset+=1; if val_len!=depth { return None; }
        let mut values=Vec::with_capacity(val_len);
        for _ in 0..val_len { if offset+32>data.len(){return None;} let mut cur=&data[offset..offset+32]; let v=F::deserialize_compressed(&mut cur).ok()?; values.push(v); offset+=32; }
        // Remaining: d_commit, h_commit, sigma, y, w
        let mut cur=&data[offset..]; let d_commit=G1Affine::deserialize_compressed(&mut cur).ok()?; let consumed=data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let h_commit=G1Affine::deserialize_compressed(&mut cur).ok()?; let consumed=data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let sigma=G1Affine::deserialize_compressed(&mut cur).ok()?; let consumed=data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let y=F::deserialize_compressed(&mut cur).ok()?; let consumed=data.len()-cur.len()-offset; offset+=consumed;
        let mut cur=&data[offset..]; let w=F::deserialize_compressed(&mut cur).ok()?;
        Some(Self { raw: PathMultiproof { commitments, indices, values, d_commit, y, h_commit, w, sigma }, depth, bytes: data })
    }
}

/// Verify the aggregated path proof against a root commitment bytes and expected leaf field element.
pub fn verify_aggregated(root: &[u8;32], proof_bytes: &[u8], expected_leaf_field: F, srs: &SrsEval) -> Result<(), OnchainVerifyError> {
    let root_g1 = G1Affine::diovjrek0ivjmeriovwmef90ivn9u34rngv[io2erbpivuneqd[kvbn9pqonvcieqwhdbvopiqernbyuiopheqwrdjnviqpdjucvniopqushvodicviebficudhcjsdnc98ehjfgbrika8isddhant jplundirt wbiberduncviudncviedbviusifffhsabnefufhbeserialize_compressed(&root[..]).map_err(|_| OnchainVerifyError::Encoding)?;
    let parsed = AggregatedProof::parse(proof_bytes).ok_or(OnchainVerifyError::Encoding)?;
    if parsed.raw.commitments.is_empty(){ return Err(OnchainVerifyError::Empty); }
    if parsed.raw.commitments[0] != root_g1 { return Err(OnchainVerifyError::RootMismatch); }
    // Basic linkage: last value equals expected leaf (other linkage checked inside external verify function's assumptions)
    if *parsed.raw.values.last().unwrap() != expected_leaf_field { return Err(OnchainVerifyError::Encoding); }
    if verify_path_multiproof(&parsed.raw, srs, expected_leaf_field) { Ok(()) } else { Err(OnchainVerifyError::Encoding) }
}

/// Reduce a 32-byte hash to field element (little-endian mod prime)
pub fn hash_bytes_to_field(bytes: &[u8;32]) -> F { F::from_le_bytes_mod_order(bytes) }
