use pinocchio::pubkey::Pubkey;

#[repr(C)]
pub struct ClaimStatus {
    /// Authority that claimed the tokens.
    pub claimant: Pubkey,
    /// Locked amount  
    pub locked_amount: u64,
    /// Locked amount withdrawn
    pub locked_amount_withdrawn: u64,
    /// Unlocked amount
    pub unlocked_amount: u64,
}

impl ClaimStatus {
    pub const LEN: usize = core::mem::size_of::<ClaimStatus>();
}
