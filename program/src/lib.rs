#![no_std]
#![allow(unexpected_cfgs)]

extern crate alloc;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;
mod error;
pub mod instruction;
pub mod state;
mod utils;
mod srs;
mod verify_onchain;
pinocchio_pubkey::declare_id!("GYbv43vv7oxEasGkedttXrWGf5JANfY6rpAMUBpKukUH");
