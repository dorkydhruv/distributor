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
    state::{ClaimStatus, VerkleDistributor},
    utils::blake3_hash,
    srs::{assert_srs_populated, srs_bytes_from_distributor},
    verify_onchain::{verify_aggregated as verify_path_aggregated, hash_bytes_to_field},
};
use kzg::srs_from_storage;
use ark_bn254::Fr as F;

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
    pub amount_unlocked: u64, // 0..8
    pub amount_locked: u64,   // 8..16
    pub distributor_bump: u8, // 16
    pub claim_status_bump: u8, //17
    pub proof_len: u16,       // 18..20 (little-endian)
}

impl<'a> TryFrom<&'a [u8]> for NewClaimInstructionData {
    type Error = ProgramError;
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() < 20 { return Err(ProgramError::InvalidInstructionData); }
        let amount_unlocked = u64::from_le_bytes(value[0..8].try_into().unwrap());
        let amount_locked = u64::from_le_bytes(value[8..16].try_into().unwrap());
        let distributor_bump = value[16];
        let claim_status_bump = value[17];
        let proof_len = u16::from_le_bytes(value[18..20].try_into().unwrap());
        Ok(Self { amount_unlocked, amount_locked, distributor_bump, claim_status_bump, proof_len })
    }
}

pub struct NewClaim<'a> {
    pub accounts: NewClaimAccounts<'a>,
    pub instruction_data: NewClaimInstructionData,
    pub proof_bytes: &'a [u8],
}

impl<'a> TryFrom<(&'a [AccountInfo], &'a [u8])> for NewClaim<'a> {
    type Error = ProgramError;
    fn try_from(value: (&'a [AccountInfo], &'a [u8])) -> Result<Self, Self::Error> {
        let accounts: NewClaimAccounts = value.0.try_into()?;
        let header: NewClaimInstructionData = value.1.try_into()?;
        let total_len = 20 + header.proof_len as usize;
        if value.1.len() != total_len { return Err(ProgramError::InvalidInstructionData); }
        let proof_slice = &value.1[20..total_len];
        Ok(Self { accounts, instruction_data: header, proof_bytes: proof_slice })
    }
}

impl<'a> NewClaim<'a> {
    pub const DISC: &'a u8 = &1;
    pub fn process(&mut self) -> ProgramResult {
        // clock retrieval reserved for future time-based claim logic; removed unused variable to satisfy lints
        let _ = Clock::get()?; // keep syscall side-effects minimal

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

        // Leaf hashing must match tree construction: hash(LEAF_PREFIX, claimant, amount_unlocked, amount_locked)
        let node_hash = blake3_hash(&[
            LEAF_PREFIX,
            self.accounts.claimant.key(),
            self.instruction_data.amount_unlocked.to_le_bytes().as_ref(),
            self.instruction_data.amount_locked.to_le_bytes().as_ref(),
        ])?;
        let leaf_f: F = hash_bytes_to_field(&node_hash);

        let root = distributor.root; // [u8;32]
        // Ensure SRS populated before attempting verification
        assert_srs_populated(distributor)?;
        let (g1_lagrange, g2_gen, g2_tau) = srs_bytes_from_distributor(distributor);
        // Reconstruct SRS (verification-only)
        let srs = srs_from_storage(g1_lagrange, g2_gen, g2_tau).ok_or(ProgramError::InvalidAccountData)?;
        // Verify aggregated path multiproof
        match verify_path_aggregated(&root, self.proof_bytes, leaf_f, &srs) {
            Ok(()) => {},
            Err(_e) => return Err(ErrorCode::InvalidProof.into()),
        }

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
