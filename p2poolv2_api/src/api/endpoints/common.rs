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

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget};
    use p2poolv2_lib::store::dag_store::{ShareInfo, UncleInfo};

    #[test]
    fn test_share_info_serialization() {
        let share_info = ShareInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            height: 42,
            miner_pubkey: "02aabbccdd".to_string(),
            timestamp: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1b4188f5),
            uncles: vec![],
        };

        let json = serde_json::to_string(&share_info).unwrap();
        assert!(json.contains("\"height\":42"));
        assert!(json.contains("\"miner_pubkey\":\"02aabbccdd\""));
        assert!(json.contains("\"timestamp\":1700000000"));
    }

    #[test]
    fn test_share_info_with_uncles_serialization() {
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

        let json = serde_json::to_string(&share_info).unwrap();
        assert!(json.contains("\"02uncle\""));
        assert!(json.contains("\"height\":41"));
    }

    #[test]
    fn test_uncle_info_serialization() {
        let uncle = UncleInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            miner_pubkey: "02aabb".to_string(),
            timestamp: 1_700_000_005,
            height: Some(10),
        };

        let json = serde_json::to_string(&uncle).unwrap();
        assert!(json.contains("\"miner_pubkey\":\"02aabb\""));
        assert!(json.contains("\"timestamp\":1700000005"));
        assert!(json.contains("\"height\":10"));
    }

    #[test]
    fn test_uncle_info_with_no_height_serialization() {
        let uncle = UncleInfo {
            blockhash: BlockHash::all_zeros(),
            prev_blockhash: BlockHash::all_zeros(),
            miner_pubkey: "02ccdd".to_string(),
            timestamp: 1_700_000_005,
            height: None,
        };

        let json = serde_json::to_string(&uncle).unwrap();
        assert!(json.contains("\"height\":null"));
    }
}
