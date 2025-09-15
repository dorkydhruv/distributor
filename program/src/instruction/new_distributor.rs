use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;
use pinocchio_token::state::TokenAccount;

use crate::state::VerkleDistributor;

pub struct NewDistributorAccounts<'a> {
    pub distributor: &'a AccountInfo,
    pub clawback_receiver: &'a AccountInfo,
    pub mint: &'a AccountInfo,
    pub token_vault: &'a AccountInfo,
    pub admin: &'a AccountInfo,
}
impl<'a> TryFrom<&'a [AccountInfo]> for NewDistributorAccounts<'a> {
    type Error = ProgramError;

    fn try_from(value: &'a [AccountInfo]) -> Result<Self, Self::Error> {
        let [distributor, clawback_receiver, mint, token_vault, admin, ..] = value else {
            return Err(ProgramError::NotEnoughAccountKeys);
        };

        // Admin must be a signer
        if !admin.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        // Distributor is already initialized
        if distributor.is_owned_by(&pinocchio_system::ID) {
            return Err(ProgramError::AccountAlreadyInitialized);
        }

        // Clawback receiver token account must match mint
        let clawback_receiver_token_account = TokenAccount::from_account_info(clawback_receiver)?;
        if clawback_receiver_token_account.mint().ne(mint.key()) {
            return Err(ProgramError::InvalidAccountData);
        }

        // Token vault must match mint
        // We expect the token account to initialized in the client side
        let token_vault_token_account = TokenAccount::from_account_info(token_vault)?;
        if token_vault_token_account.mint().ne(mint.key()) {
            return Err(ProgramError::InvalidAccountData);
        }
        if token_vault_token_account.owner().ne(distributor.key()) {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(Self {
            distributor,
            clawback_receiver,
            mint,
            token_vault,
            admin,
        })
    }
}

#[repr(C)]
pub struct NewDistributorInstructionData {
    pub version: u64,
    pub root: [u8; 32],
    pub max_total_claim: u64,
    pub max_num_nodes: u64,
    pub start_vesting_ts: i64,
    pub end_vesting_ts: i64,
    pub clawback_start_ts: i64,
    pub bump: u8,
}

impl<'a> TryFrom<&'a [u8]> for NewDistributorInstructionData {
    type Error = ProgramError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() != core::mem::size_of::<Self>() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let data = unsafe { &*(value.as_ptr() as *const Self) };
        Ok(Self {
            version: data.version,
            root: data.root,
            max_total_claim: data.max_total_claim,
            max_num_nodes: data.max_num_nodes,
            start_vesting_ts: data.start_vesting_ts,
            end_vesting_ts: data.end_vesting_ts,
            clawback_start_ts: data.clawback_start_ts,
            bump: data.bump,
        })
    }
}

pub struct NewDistributor<'a> {
    pub accounts: NewDistributorAccounts<'a>,
    pub data: NewDistributorInstructionData,
}

impl<'a> TryFrom<(&'a [AccountInfo], &'a [u8])> for NewDistributor<'a> {
    type Error = ProgramError;

    fn try_from(value: (&'a [AccountInfo], &'a [u8])) -> Result<Self, Self::Error> {
        let accounts = NewDistributorAccounts::try_from(value.0)?;
        let data = NewDistributorInstructionData::try_from(value.1)?;
        Ok(Self { accounts, data })
    }
}

impl<'a> NewDistributor<'a> {
    pub const DISC: &'a u8 = &0;
    pub fn process(&mut self) -> ProgramResult {
        pinocchio::msg!("Processing NewDistributor");
        let curr_ts = Clock::get()?.unix_timestamp;
        assert!(
            self.data.start_vesting_ts < self.data.end_vesting_ts,
            "Start timestamp must be before end timestamp"
        );
        assert!(
            self.data.start_vesting_ts > curr_ts
                && self.data.end_vesting_ts > curr_ts
                && self.data.clawback_start_ts > curr_ts,
            "All timestamps must be in the future"
        );
        assert!(
            self.data.clawback_start_ts > self.data.end_vesting_ts,
            "Clawback start timestamp must be after end timestamp"
        );
        assert!(
            self.data.clawback_start_ts
                >= self
                    .data
                    .end_vesting_ts
                    .checked_add(86400)
                    .ok_or(ProgramError::InvalidInstructionData)?,
            "Clawback start timestamp must be at least one day after end timestamp"
        );

        let bump = [self.data.bump];
        let version_bytes = self.data.version.to_le_bytes();
        let seeds = [
            Seed::from(VerkleDistributor::SEED),
            Seed::from(self.accounts.mint.key().as_ref()),
            Seed::from(version_bytes.as_ref()),
            Seed::from(&bump[..]),
        ];
        let distributor_signer = Signer::from(&seeds[..]);

        pinocchio_log::log!("distributor signer created");

        (CreateAccount {
            from: self.accounts.admin,
            to: self.accounts.distributor,
            lamports: Rent::get()?.minimum_balance(VerkleDistributor::LEN),
            space: VerkleDistributor::LEN as u64,
            owner: &crate::ID,
        })
        .invoke_signed(&[distributor_signer])?;

        pinocchio_log::log!("distributor account created");

        VerkleDistributor::initialize(
            unsafe {
                VerkleDistributor::unpack(self.accounts.distributor.borrow_mut_data_unchecked())
            },
            self.data.version,
            self.data.root,
            *self.accounts.mint.key(),
            *self.accounts.token_vault.key(),
            self.data.max_total_claim,
            self.data.max_num_nodes,
            self.data.start_vesting_ts,
            self.data.end_vesting_ts,
            self.data.clawback_start_ts,
            *self.accounts.clawback_receiver.key(),
            *self.accounts.admin.key(),
            self.data.bump,
        );
        Ok(())
    }
}
