use pinocchio::{program_error::ProgramError, pubkey::Pubkey, syscalls::sol_blake3};

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
