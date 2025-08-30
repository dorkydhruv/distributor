use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use blake3::{hash, Hash, Hasher};

use crate::csv_entry::{AirdropCategory, CsvEntry};
pub const MINT_DECIMALS: u32 = 9;

macro_rules! hashv {
    ($($expr:expr),*) => {{
        
        let mut hash = Hasher::new();
        $(
            hash.update($expr);
        )*
        hash.finalize()
    }};
}

/// Represents the claim information for an account.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TreeNode {
    /// Pubkey of the claimant; will be responsible for signing the claim
    pub claimant: [u8;32],
    /// Claimant's proof of inclusion in the Verkle Tree
    pub proof: Option<Vec<[u8; 32]>>,
    /// Total amount unlocked under staker allocation
    pub total_unlocked_staker: u64,
    /// Total amount locked under staker allocation
    pub total_locked_staker: u64,
    /// Total amount unlocked under searcher allocation
    pub total_unlocked_searcher: u64,
    /// Total amount locked under searcher allocation
    pub total_locked_searcher: u64,
    /// Total amount unlocked under validator allocation
    pub total_unlocked_validator: u64,
    /// Total amount locked under validator allocation
    pub total_locked_validator: u64,
}

impl TreeNode {
    pub fn hash(&self) -> Hash {
        hashv!(self.claimant.as_ref(),&self.total_amount().to_le_bytes(), &self.total_locked_staker.to_be_bytes())
    }

    // pub fn hash_to_field_element(&self) -> Fr {
    //     Fr::from_le_bytes_mod_order(self.hash().as_bytes())
    // }

    /// Return total amount of locked and unlocked amount for this claimant
    pub fn total_amount(&self) -> u64 {
        self.amount_unlocked()
            .checked_add(self.amount_locked())
            .unwrap()
    }

    /// Get total amount of unlocked tokens for this claimant
    pub fn amount_unlocked(&self) -> u64 {
        self.total_unlocked_searcher
            .checked_add(self.total_unlocked_validator)
            .unwrap()
            .checked_add(self.total_unlocked_staker)
            .unwrap()
    }

    /// Get total amount of locked tokens for this claimant
    pub fn amount_locked(&self) -> u64 {
        self.total_locked_searcher
            .checked_add(self.total_locked_validator)
            .unwrap()
            .checked_add(self.total_locked_staker)
            .unwrap()
    }
}

/// Converts a ui amount to a token amount (with decimals)
fn ui_amount_to_token_amount(amount: u64) -> u64 {
    amount * 10u64.checked_pow(MINT_DECIMALS).unwrap()
}

impl From<CsvEntry> for TreeNode {
    fn from(entry: CsvEntry) -> Self {
        let mut node = Self {
            claimant: [0;32],
            proof: None,
            total_unlocked_staker: 0,
            total_locked_staker: 0,
            total_unlocked_searcher: 0,
            total_locked_searcher: 0,
            total_unlocked_validator: 0,
            total_locked_validator: 0,
        };

        // CSV entry uses UI amounts; we convert to native amounts here
        let amount_unlocked = ui_amount_to_token_amount(entry.amount_unlocked);
        let amount_locked = ui_amount_to_token_amount(entry.amount_locked);
        match entry.category {
            AirdropCategory::Staker => {
                node.total_unlocked_staker = amount_unlocked;
                node.total_locked_staker = amount_locked;
            }
            AirdropCategory::Validator => {
                node.total_unlocked_validator = amount_unlocked;
                node.total_locked_validator = amount_locked;
            }
            AirdropCategory::Searcher => {
                node.total_unlocked_searcher = amount_unlocked;
                node.total_locked_searcher = amount_locked;
            }
        }
        node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_tree_node() {
        let tree_node = TreeNode {
            claimant: [0;32],
            proof: None,
            total_unlocked_staker: 0,
            total_locked_staker: 0,
            total_unlocked_searcher: 0,
            total_locked_searcher: 0,
            total_unlocked_validator: 0,
            total_locked_validator: 0,
        };
        let serialized = serde_json::to_string(&tree_node).unwrap();
        let deserialized: TreeNode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tree_node, deserialized);
    }

    #[test]
    fn test_ui_amount_to_token_amount() {
        let ui_amount = 5;
        let token_amount = ui_amount_to_token_amount(ui_amount);
        assert_eq!(token_amount, 5_000_000_000);
    }
}
