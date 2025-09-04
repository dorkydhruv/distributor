use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use pinocchio_token::state::TokenAccount;

use crate::{
    error::ErrorCode,
    state::{claim_status, ClaimStatus, VerkleDistributor},
    utils::blake3_hash,
};

const LEAF_PREFIX: &[u8] = &[0];

pub struct NewClaimAccounts<'a> {
    pub distributor: &'a AccountInfo,
    pub claim_status: &'a AccountInfo,
    pub from: &'a AccountInfo,
    pub to: &'a AccountInfo,
    pub claimant: &'a AccountInfo,
}

impl<'a> TryFrom<&'a [AccountInfo]> for NewClaimAccounts<'a> {
    type Error = ProgramError;

    fn try_from(value: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [distributor, claim_status, from, to, claimant, ..] = value else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        if !claimant.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        if !distributor.is_owned_by(&pinocchio_system::ID) && distributor.lamports().eq(&0) {
            return Err(ProgramError::UninitializedAccount);
        }

        if !claim_status.is_owned_by(&pinocchio_system::ID) && claim_status.lamports().ne(&0) {
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

        Ok(Self {
            distributor,
            claim_status,
            from,
            to,
            claimant,
        })
    }
}

#[repr(C)]
pub struct NewClaimInstructionData {
    pub amount_unlocked: u64, //8
    pub amount_locked: u64,   //8
    pub proof: [u8; 32],      //32
    pub distributor_bump: u8,
    pub claim_status_bump: u8,
}

impl<'a> TryFrom<&'a [u8]> for NewClaimInstructionData {
    type Error = ProgramError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != core::mem::size_of::<Self>() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let amount_unlocked = u64::from_le_bytes(
            value[0..8]
                .try_into()
                .or(Err(ProgramError::InvalidInstructionData))?,
        );
        let amount_locked = u64::from_le_bytes(
            value[8..16]
                .try_into()
                .or(Err(ProgramError::InvalidInstructionData))?,
        );
        let proof = value[16..48]
            .try_into()
            .or(Err(ProgramError::InvalidInstructionData))?;
        let distributor_bump = value[48];
        let claim_status_bump = value[49];

        Ok(Self {
            amount_unlocked,
            amount_locked,
            proof,
            distributor_bump,
            claim_status_bump,
        })
    }
}

pub struct NewClaim<'a> {
    pub accounts: NewClaimAccounts<'a>,
    pub instruction_data: NewClaimInstructionData,
}

impl<'a> TryFrom<(&'a [AccountInfo], &'a [u8])> for NewClaim<'a> {
    type Error = ProgramError;

    fn try_from(value: (&'a [AccountInfo], &'a [u8])) -> Result<Self, Self::Error> {
        Ok(Self {
            accounts: value.0.try_into()?,
            instruction_data: value.1.try_into()?,
        })
    }
}

impl<'a> NewClaim<'a> {
    pub const DISC: &'a u8 = &1;
    pub fn process(&mut self) -> ProgramResult {
        let curr_ts = Clock::get()?.unix_timestamp;

        let distributor = unsafe {
            VerkleDistributor::unpack(self.accounts.distributor.borrow_mut_data_unchecked())
        };

        if distributor.clawed_back.ne(&0) {
            return Err(ErrorCode::ClaimExpired.into());
        }

        distributor.num_nodes_claimed = u64::from_le_bytes(distributor.num_nodes_claimed)
            .checked_add(1)
            .ok_or(ErrorCode::ArithmeticError)?
            .to_le_bytes();

        if distributor.num_nodes_claimed.gt(&distributor.max_num_nodes) {
            return Err(ErrorCode::MaxNodesExceeded.into());
        }

        let node_hash = blake3_hash(&[
            self.accounts.claimant.key(),
            self.instruction_data.amount_locked.to_le_bytes().as_ref(),
            self.instruction_data.amount_unlocked.to_le_bytes().as_ref(),
        ])?;
        let node = blake3_hash(&[LEAF_PREFIX, node_hash.as_ref()])?;

        let root = distributor.root;

        // verify(&self.instruction_data.proof, root, node)?; // do the stuff needed for this

        if self.accounts.claim_status.lamports().ne(&0) {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        // Create claim status account
        let bump = [self.instruction_data.claim_status_bump];
        let claim_status_seeds = [
            Seed::from(ClaimStatus::DISCRIMINATOR.as_ref()),
            Seed::from(self.accounts.claimant.key().as_ref()),
            Seed::from(self.accounts.distributor.key().as_ref()),
            Seed::from(&bump[..]),
        ];
        let claim_status_signer = Signer::from(&claim_status_seeds[..]);

        (CreateAccount {
            from: self.accounts.claimant,
            to: self.accounts.claim_status,
            lamports: Rent::get()?.minimum_balance(ClaimStatus::LEN),
            space: ClaimStatus::LEN as u64,
            owner: &crate::ID,
        }
        .invoke_signed(&[claim_status_signer])?);

        let claim_status =
            unsafe { ClaimStatus::unpack(self.accounts.claim_status.borrow_mut_data_unchecked()) };

        claim_status.claimant = *self.accounts.claimant.key();
        claim_status.locked_amount = self.instruction_data.amount_locked;
        claim_status.unlocked_amount = self.instruction_data.amount_unlocked;
        claim_status.locked_amount_withdrawn = 0;

        let distributor_bump = [self.instruction_data.distributor_bump];
        let distributor_seeds = [
            Seed::from(VerkleDistributor::SEED),
            Seed::from(distributor.mint.as_ref()),
            Seed::from(distributor.version.as_ref()),
            Seed::from(&distributor_bump[..]),
        ];
        let distributor_signer = Signer::from(&distributor_seeds[..]);

        pinocchio_token::instructions::Transfer {
            from: self.accounts.from,
            to: self.accounts.to,
            authority: self.accounts.distributor,
            amount: self.instruction_data.amount_unlocked,
        }
        .invoke_signed(&[distributor_signer])?;

        distributor.total_amount_claimed = u64::from_le_bytes(distributor.total_amount_claimed)
            .checked_add(claim_status.unlocked_amount)
            .ok_or(ErrorCode::ArithmeticError)?
            .to_le_bytes();

        if distributor
            .total_amount_claimed
            .gt(&distributor.max_total_claim)
        {
            return Err(ErrorCode::ExceededMaxClaim.into());
        }

        Ok(())
    }
}
