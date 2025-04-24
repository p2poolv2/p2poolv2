// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use crate::shares::miner_message::MinerShare;
use crate::shares::ShareHeader;
use crate::utils::time_provider::TimeProvider;
use std::error::Error;
use tracing::{info, warn};

use num_bigint::BigUint;
use num_traits::FromPrimitive;
use rust_decimal::prelude::*;
use rust_decimal::Decimal;
use sha2::{Digest, Sha256};

/// Handle ShareHeaders received from a peer
/// We need to:
/// 1. TODO: Store the headers
/// 2. TODO: Push the header into a task queue to fetch txs to build the ShareBlock
/// 3. TODO: We need to start a task in node to pull from the task queue and send getData message for txs

/// Converts a given difficulty into a target hash (the higher the difficulty, the lower the target).
fn diff_to_target(diff: Decimal) -> [u8; 32] {
    // max_target = 0xffff * 2^208 (Bitcoin-style max target)
    let max_target = BigUint::from_u64(0xFFFF).unwrap() * BigUint::from_u64(2).unwrap().pow(208);

    // Convert the Decimal diff into a BigUint for safe calculations
    let diff_f64 = diff.to_f64().unwrap_or(1.0); // Ensure safe fallback if diff is too small
    let diff_big = BigUint::from_f64(diff_f64).unwrap_or(BigUint::from_u64(1).unwrap());

    // Calculate the target as max_target / diff
    let target = max_target / diff_big;

    // Convert the target BigUint to a byte array
    let mut target_bytes = [0u8; 32];
    let target_bytes_vec = target.to_bytes_be();

    let target_len = target_bytes_vec.len();
    for i in 0..target_len {
        target_bytes[32 - target_len + i] = target_bytes_vec[i];
    }

    target_bytes
}

impl ShareHeader {
    /// Validate the Proof-of-Work on the share header
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(self.miner_share.nonce.as_bytes());
        hasher.update(self.miner_share.nonce2.as_bytes());
        hasher.update(self.miner_share.enonce1.as_bytes());
        hasher.update(self.miner_share.ntime.to_string().as_bytes());
        hasher.update(&self.merkle_root);
        hasher.update(&self.miner_pubkey.to_bytes());

        if let Some(prev) = &self.prev_share_blockhash {
            hasher.update(prev);
        }

        for uncle in &self.uncles {
            hasher.update(uncle);
        }

        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result);
        hash_bytes
    }

    /// Validate the PoW by checking if the hash is below the target derived from difficulty
    pub fn validate_pow(&self) -> bool {
        let hash = self.hash();
        let target = diff_to_target(self.miner_share.diff);
        println!("Hash: {:x?}", hash);
        println!("Target: {:x?}", target);
        hash <= target
    }
}
pub async fn handle_share_headers(
    share_headers: Vec<ShareHeader>,
    _chain_handle: ChainHandle,
    _time_provider: &impl TimeProvider,
) -> Result<(), Box<dyn Error>> {
    info!("Received share headers: {:?}", share_headers);
    for share_header in share_headers {
        if !share_header.validate_pow() {
            warn!("Invalid PoW for share header: {:?}", share_header);
            return Err("Invalid PoW".into());
        }
    }
    Ok(())
}
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use bitcoin::hashes::sha256d::Hash as Sha256dHash;
//     use bitcoin::hashes::Hash;
//     use bitcoin::{BlockHash, PublicKey, TxMerkleNode};
//     use rust_decimal::Decimal;
//     use std::str::FromStr;

//     // Mock function to return a dummy PublicKey for testing
//     fn dummy_pubkey() -> PublicKey {
//         PublicKey::from_str("02c0eea8e11a299fda655b88e3f1c0cf855b78805b0ccedb1a90dbdd8f6ab6be9e")
//             .unwrap()
//     }

//     #[test]
//     fn test_valid_pow() {
//         //  ShareHeader with mock data
//         let share_header = ShareHeader {
//             miner_share: MinerShare {
//                 workinfoid: 12345,
//                 clientid: 67890,
//                 enonce1: "test_enonce1".to_string(),
//                 nonce2: "test_nonce2".to_string(),
//                 nonce: "test_nonce".to_string(),
//                 ntime: bitcoin::absolute::Time::from_consensus(1631023200).unwrap(),
//                 diff: Decimal::new(100, 2), // Some difficulty
//                 sdiff: Decimal::new(100, 2),
//                 hash: BlockHash::from_slice(&[0u8; 32]).unwrap(),
//                 result: true,
//                 errn: 0,
//                 createdate: "2024-01-01".to_string(),
//                 createby: "test_creator".to_string(),
//                 createcode: "test_code".to_string(),
//                 createinet: "127.0.0.1".to_string(),
//                 workername: "test_worker".to_string(),
//                 username: "test_user".to_string(),
//                 address: "test_address".to_string(),
//                 agent: "test_agent".to_string(),
//             },

//             prev_share_blockhash: None,
//             uncles: vec![],
//             miner_pubkey: dummy_pubkey(),
//             merkle_root: TxMerkleNode::from_raw_hash(Sha256dHash::all_zeros()),
//         };

//         // Expecting valid PoW based on the difficulty and data
//         assert!(share_header.validate_pow());
//     }
// }
