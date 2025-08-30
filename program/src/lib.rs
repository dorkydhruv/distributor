#![no_std]
#![allow(unexpected_cfgs)]

#[cfg(feature = "std")]
extern crate std;
#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;
mod error;
mod instruction;
pub mod state;
pinocchio_pubkey::declare_id!("AvvaLMBjGBWNamh1qV72gzG412kiZWVFHu2PMi36Bg3G");
