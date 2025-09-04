use pinocchio::{
    account_info::AccountInfo, no_allocator, nostd_panic_handler, program_entrypoint,
    program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

use crate::instruction::{NewClaim, NewDistributor};

// This is the entrypoint for the program.
program_entrypoint!(process_instruction);
//Do not allocate memory.
no_allocator!();
// Use the no_std panic handler.
nostd_panic_handler!();

#[inline(always)]
fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data.split_first() {
        Some((NewDistributor::DISC, instruction_data)) => {
            NewDistributor::try_from((accounts, instruction_data))?.process()
        }
        Some((NewClaim::DISC, instruction_data)) => {
            NewClaim::try_from((accounts, instruction_data))?.process()
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
