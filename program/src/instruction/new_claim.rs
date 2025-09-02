use pinocchio::{account_info::AccountInfo, program_error::ProgramError, sysvars::{clock::Clock, Sysvar}, ProgramResult};
use pinocchio_token::state::TokenAccount;

use crate::{error::ErrorCode, state::VerkleDistributor};

pub struct NewClaimAccounts<'a>{
    pub distributor: &'a AccountInfo,
    pub claim_status: &'a AccountInfo,
    pub from: &'a AccountInfo,
    pub to: &'a AccountInfo,
    pub claimant: &'a AccountInfo,
}

impl<'a> TryFrom<&'a [AccountInfo] >for NewClaimAccounts<'a>{
    type Error = ProgramError;

    fn try_from(value: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [distributor, claim_status, from, to, claimant, ..] = value else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        if !claimant.is_signer(){
            return Err(ProgramError::MissingRequiredSignature);
        }

        if !distributor.is_owned_by(&pinocchio_system::ID) && distributor.lamports().eq(&0){
            return Err(ProgramError::UninitializedAccount);
        }

        if !claim_status.is_owned_by(&pinocchio_system::ID) && claim_status.lamports().ne(&0){
            return Err(ProgramError::UninitializedAccount);
        }

        let from_token_account = TokenAccount::from_account_info(from)?;
        if from_token_account.owner().ne(distributor.key()) {
            return Err(ProgramError::InvalidAccountData);
        }

        let to_token_account = TokenAccount::from_account_info(to)?;
        if to_token_account.owner().ne(claimant.key()) {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(Self{
            distributor,
            claim_status,
            from,
            to,
            claimant
        })
    }
} 

#[repr(C)]
pub struct NewClaimInstructionData {
    pub amount_unlocked: u64, //8
    pub amount_locked: u64, //8
    pub proof: [u8; 32], //32
}

impl<'a> TryFrom<&'a [u8]> for NewClaimInstructionData {
    type Error = ProgramError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != core::mem::size_of::<Self>() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let amount_unlocked = u64::from_le_bytes(value[0..8].try_into().or(Err(ProgramError::InvalidInstructionData))?);
        let amount_locked = u64::from_le_bytes(value[8..16].try_into().or(Err(ProgramError::InvalidInstructionData))?);
        let proof = value[16..48].try_into().or(Err(ProgramError::InvalidInstructionData))?;

        Ok(Self {
            amount_unlocked,
            amount_locked,
            proof,
        })
    }
}

pub struct NewClaim<'a>{
    pub accounts: NewClaimAccounts<'a>,
    pub instruction_data: NewClaimInstructionData,
}

impl<'a> TryFrom<(&'a [AccountInfo], &'a [u8])> for NewClaim<'a>{
    type Error = ProgramError;

    fn try_from(value: (&'a [AccountInfo], &'a [u8])) -> Result<Self, Self::Error> {
        Ok(Self{
            accounts: value.0.try_into()?,
            instruction_data: value.1.try_into()?
        })
    }
}

impl<'a> NewClaim<'a> {
    pub const DISC: &'a usize = &1;
    pub fn process(&mut self)-> ProgramResult{
        let curr_ts = Clock::get()?.unix_timestamp;

        let distributor = unsafe{VerkleDistributor::unpack(self.accounts.distributor.borrow_mut_data_unchecked())};

        if distributor.clawed_back.ne(&0){
            return Err(ErrorCode::ClaimExpired.into());
        }

        distributor.num_nodes_claimed = u64::from_le_bytes(distributor.num_nodes_claimed).checked_add(1).ok_or(ErrorCode::ArithmeticError)?.to_le_bytes();

        if distributor.num_nodes_claimed.gt(&distributor.max_num_nodes) {
            return Err(ErrorCode::MaxNodesExceeded.into());
        }

        


        Ok(())
    }

}


