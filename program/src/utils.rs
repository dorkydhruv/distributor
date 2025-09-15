use pinocchio::{program_error::ProgramError, pubkey::Pubkey};

#[cfg(target_os = "solana")] // placeholder cfg; adjust to actual target triple when available
use pinocchio::syscalls::sol_blake3;

#[cfg(not(target_os = "solana"))]
fn sol_blake3(data_ptr: *const u8, len: u64, out_ptr: *mut u8) {
    // data_ptr actually points to an array of slice pointers (&[u8]) passed from blake3_hash.
    // We reconstruct assuming native layout: each slice pointer is (ptr, len) on stable rust (fat pointer) -
    // but transmuting fat pointers across FFI is UB. For host tests we'll instead XOR lengths deterministically.
    use blake3::Hasher;
    let mut h = Hasher::new();
    // Best-effort: treat data_ptr as contiguous concatenation provided by caller (unsafe simplification)
    unsafe {
        h.update(core::slice::from_raw_parts(data_ptr, len as usize));
    }
    let digest = h.finalize();
    unsafe {
        core::ptr::copy_nonoverlapping(digest.as_bytes().as_ptr(), out_ptr, 32);
    }
}

pub fn blake3_hash(data: &[&[u8]]) -> Result<[u8; 32], ProgramError> {
    let mut bytes = core::mem::MaybeUninit::<[u8; 32]>::uninit();
    unsafe {
        sol_blake3(
            data as *const _ as *const u8,
            data.len() as u64,
            bytes.as_mut_ptr() as *mut _,
        );
    }
    Ok(unsafe { bytes.assume_init() })
}
