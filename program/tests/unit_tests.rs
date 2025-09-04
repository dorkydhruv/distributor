use mollusk_svm::result::{Check, ProgramResult};
use mollusk_svm::{program, Mollusk};
use solana_sdk::account::{Account, WritableAccount};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::native_token::LAMPORTS_PER_SOL;
use solana_sdk::program_option::COption;
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey;
use solana_sdk::pubkey::Pubkey;
extern crate std;
use std::vec;

use pinocchio_distributor::instruction::*;
use pinocchio_distributor::state::*;

pub const PROGRAM: Pubkey = Pubkey::new_from_array(pinocchio_distributor::ID);
pub const RENT: Pubkey = pubkey!("SysvarRent111111111111111111111111111111111");

pub fn mollusk() -> Mollusk {
    let mut mollusk = Mollusk::new(&PROGRAM, "../target/deploy/pinocchio_distributor");
    mollusk.add_program(
        &spl_token::ID,
        "tests/elfs/spl_token",
        &mollusk_svm::program::loader_keys::LOADER_V3,
    );
    mollusk
}

pub trait AccountExt {
    fn refresh(
        &mut self,
        account_pubkey: &Pubkey,
        result: mollusk_svm::result::InstructionResult,
    ) -> &mut Self;
}

impl AccountExt for Account {
    fn refresh(
        &mut self,
        account_pubkey: &Pubkey,
        result: mollusk_svm::result::InstructionResult,
    ) -> &mut Self {
        *self = result.get_account(account_pubkey).unwrap().clone();
        self
    }
}

pub fn get_spl_token_program() -> (Pubkey, Account) {
    (
        spl_token::ID,
        program::create_program_account_loader_v3(&spl_token::ID),
    )
}
