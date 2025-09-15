#![allow(dead_code)]
use crate::state::VerkleDistributor;
use crate::error::ErrorCode;
use pinocchio::program_error::ProgramError;

// We re-import minimal types from verify + kzg crates behind feature gates not available in on-chain program.
// For now we duplicate minimal verification needed: compressed G1 deserialization and transcript hashing
// are handled inside verify crate off-chain. On-chain we only need to expose raw bytes for an external verifier
// or (future) in-program pairing precompile once available. Thus this module currently only reconstructs the
// SRS byte slices so the caller can pass them to an off-chain verifier via CPI or simulated environment.

/// Reconstruct raw SRS byte references from the distributor account.
pub fn srs_bytes_from_distributor(dist: &VerkleDistributor) -> (
    &[[u8;32]; 32],
    &[u8;64],
    &[u8;64]
) {
    (&dist.g1_lagrange, &dist.g2_gen, &dist.g2_tau)
}

/// Basic sanity check that SRS has been populated (not all zeros for first G1 and g2_gen).
pub fn assert_srs_populated(dist: &VerkleDistributor) -> Result<(), ProgramError> {
    if dist.g1_lagrange[0] == [0u8;32] || dist.g2_gen == [0u8;64] { return Err(ErrorCode::UninitializedSrs.into()); }
    Ok(())
}

/// Convenience to return root bytes (already stored compressed G1 of 32 bytes)
pub fn root_bytes(dist: &VerkleDistributor) -> &[u8;32] { &dist.root }
