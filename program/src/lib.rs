#![no_std]
#![allow(unexpected_cfgs)]

#[cfg(feature = "std")]
extern crate std;
#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;
mod error;
pub mod instruction;
pub mod state;
mod utils;
pinocchio_pubkey::declare_id!("GYbv43vv7oxEasGkedttXrWGf5JANfY6rpAMUBpKukUH");
