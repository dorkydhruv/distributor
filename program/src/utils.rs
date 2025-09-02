use pinocchio::{program_error::ProgramError, pubkey::Pubkey, syscalls::sol_blake3};

pub fn node_hash(claimant_account: &Pubkey, amount_locked: &[u8], amount_unlocked: &[u8])-> Result<[u8;32],ProgramError> {
    let val = &[claimant_account, amount_locked, amount_unlocked];
    let mut bytes = core::mem::MaybeUninit::<[u8; 32]>::uninit();
    unsafe {
        sol_blake3(val as *const _ as *const u8, val.len() as u64, bytes.as_mut_ptr() as *mut _);
    }
    Ok(unsafe { bytes.assume_init() })
}
