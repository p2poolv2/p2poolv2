// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
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

use bitcoin::Target;
use p2poolv2_lib::store::dag_store::{ShareInfo, UncleInfo};
use serde::Serialize;

/// JSON response for a share with its uncles.
#[derive(Serialize)]
pub struct ShareInfoResponse {
    pub blockhash: String,
    pub prev_blockhash: String,
    pub height: u32,
    pub miner_pubkey: String,
    pub timestamp: u32,
    pub bits: String,
    pub difficulty: f64,
    pub uncles: Vec<UncleInfoResponse>,
}

/// JSON response for an uncle share.
#[derive(Serialize)]
pub struct UncleInfoResponse {
    pub blockhash: String,
    pub prev_blockhash: String,
    pub miner_pubkey: String,
    pub timestamp: u32,
    pub height: Option<u32>,
}

impl From<ShareInfo> for ShareInfoResponse {
    fn from(share: ShareInfo) -> Self {
        let difficulty = Target::from_compact(share.bits).difficulty_float();
        let uncles: Vec<UncleInfoResponse> = share
            .uncles
            .into_iter()
            .map(UncleInfoResponse::from)
            .collect();

        ShareInfoResponse {
            blockhash: share.blockhash.to_string(),
            prev_blockhash: share.prev_blockhash.to_string(),
            height: share.height,
            miner_pubkey: share.miner_pubkey,
            timestamp: share.timestamp,
            bits: format!("{:#x}", share.bits.to_consensus()),
            difficulty,
            uncles,
        }
    }
}

impl From<UncleInfo> for UncleInfoResponse {
    fn from(uncle: UncleInfo) -> Self {
        UncleInfoResponse {
            blockhash: uncle.blockhash.to_string(),
            prev_blockhash: uncle.prev_blockhash.to_string(),
            miner_pubkey: uncle.miner_pubkey,
            timestamp: uncle.timestamp,
            height: uncle.height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget};

    #[test]
    fn test_share_info_response_from_share_info() {
        let share_info = ShareInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            height: 42,
            miner_pubkey: "02aabbccdd".to_string(),
            timestamp: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            uncles: vec![],
        };

        let response = ShareInfoResponse::from(share_info);

        assert_eq!(response.height, 42);
        assert_eq!(response.timestamp, 1_700_000_000);
        assert_eq!(response.miner_pubkey, "02aabbccdd");
        assert_eq!(response.bits, "0x1b4188f5");
        assert!(response.difficulty > 0.0);
        assert!(response.uncles.is_empty());
        assert!(!response.blockhash.is_empty());
        assert!(!response.prev_blockhash.is_empty());
    }

    #[test]
    fn test_share_info_response_with_uncles() {
        let uncle = UncleInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            miner_pubkey: "02uncle".to_string(),
            timestamp: 1_700_000_010,
            height: Some(41),
        };

        let share_info = ShareInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            height: 42,
            miner_pubkey: "02parent".to_string(),
            timestamp: 1_700_000_020,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            uncles: vec![uncle],
        };

        let response = ShareInfoResponse::from(share_info);

        assert_eq!(response.uncles.len(), 1);
        assert_eq!(response.uncles[0].miner_pubkey, "02uncle");
        assert_eq!(response.uncles[0].timestamp, 1_700_000_010);
        assert_eq!(response.uncles[0].height, Some(41));
    }

    #[test]
    fn test_uncle_info_response_from_uncle_info() {
        let uncle = UncleInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            miner_pubkey: "02aabb".to_string(),
            timestamp: 1_700_000_005,
            height: Some(10),
        };

        let response = UncleInfoResponse::from(uncle);

        assert_eq!(response.miner_pubkey, "02aabb");
        assert_eq!(response.timestamp, 1_700_000_005);
        assert_eq!(response.height, Some(10));
        assert!(!response.blockhash.is_empty());
        assert!(!response.prev_blockhash.is_empty());
    }

    #[test]
    fn test_uncle_info_response_with_no_height() {
        let uncle = UncleInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            miner_pubkey: "02ccdd".to_string(),
            timestamp: 1_700_000_005,
            height: None,
        };

        let response = UncleInfoResponse::from(uncle);

        assert_eq!(response.height, None);
    }

    #[test]
    fn test_difficulty_computed_from_bits() {
        let share_info = ShareInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            height: 1,
            miner_pubkey: "02aa".to_string(),
            timestamp: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            uncles: vec![],
        };

        let response = ShareInfoResponse::from(share_info);

        // 0x1d00ffff is difficulty 1.0
        assert!((response.difficulty - 1.0).abs() < 0.001);
    }
}
