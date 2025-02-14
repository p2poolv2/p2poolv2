// Copyright (C) 2024 [Kulpreet Singh]
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

use crate::utils::serde_support::time::{deserialize_time, serialize_time};
use bitcoin::absolute::Time;
use bitcoin::consensus::Decodable;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub enum CkPoolMessage {
    Share(MinerShare),
    Workbase(MinerWorkbase),
}

/// Represents the work done by a miner as sent by ckpool.
/// We use Decimal for the diff and sdiff fields to avoid floating point precision issues.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct MinerShare {
    pub workinfoid: u64,
    pub clientid: u64,
    pub enonce1: String,
    pub nonce2: String,
    pub nonce: String,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub ntime: Time,
    pub diff: Decimal,
    pub sdiff: Decimal,
    pub hash: String,
    #[serde(skip)]
    pub result: bool,
    #[serde(skip)]
    pub errn: i32,
    #[serde(skip)]
    pub createdate: String,
    #[serde(skip)]
    pub createby: String,
    #[serde(skip)]
    pub createcode: String,
    #[serde(skip)]
    pub createinet: String,
    #[serde(skip)]
    pub workername: String,
    pub username: String,
    #[serde(skip)]
    pub address: String,
    #[serde(skip)]
    pub agent: String,
}

impl MinerShare {
    /// Validates the miner work against provided difficulty thresholds
    pub fn validate(&self, workbase: &MinerWorkbase) -> Result<(), String> {
        // Verify the hash meets required share difficulty
        // Convert hash to u256 for comparison
        let hash_bytes = hex::decode(&self.hash).map_err(|e| format!("Invalid hash hex: {}", e))?;

        if hash_bytes.len() != 32 {
            return Err(format!("Invalid hash length: {}", hash_bytes.len()));
        }

        // Convert nonce to bytes for verification
        let nonce_bytes =
            hex::decode(&self.nonce).map_err(|e| format!("Invalid nonce hex: {}", e))?;

        if nonce_bytes.len() != 4 {
            return Err(format!("Invalid nonce length: {}", nonce_bytes.len()));
        }

        // TODO: Implement actual hash verification against sdiff
        // This would involve:
        // 1. Reconstructing the block header with the nonce
        // 2. Hashing it to verify it matches self.hash
        // 3. Verifying the hash meets the required sdiff threshold
        // For now we just validate the formats

        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct WorkbaseTxn {
    pub txid: String,
    pub data: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct WorkbaseMerkleItem {
    pub merkle: String,
}

/// Represents the Workbase used by ckpool
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct MinerWorkbase {
    pub workinfoid: u64,
    pub gbt: Gbt,
    pub txns: Vec<WorkbaseTxn>,
    pub merkles: Vec<WorkbaseMerkleItem>,
    pub coinb1: String,
    pub coinb2: String,
    pub coinb3: String,
    pub header: String,
    pub txnbinlen: String,
    pub txnbin: String,
}

/// Represents the getblocktemplate used in ckpool as workbase
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Gbt {
    pub capabilities: Vec<String>,
    pub version: u32,
    pub rules: Vec<String>,
    pub vbavailable: serde_json::Value,
    pub vbrequired: u32,
    pub previousblockhash: String,
    pub transactions: Vec<serde_json::Value>,
    pub coinbaseaux: serde_json::Value,
    pub coinbasevalue: u64,
    pub longpollid: String,
    pub target: String,
    pub mintime: u64,
    pub mutable: Vec<String>,
    pub noncerange: String,
    pub sigoplimit: u32,
    pub sizelimit: u32,
    pub weightlimit: u32,
    pub curtime: Time,
    pub bits: String,
    pub height: u32,
    pub signet_challenge: String,
    pub default_witness_commitment: String,
    pub diff: f64,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub ntime: Time,
    pub bbversion: String,
    pub nbit: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gbt_response_deserialization() {
        let json = std::fs::read_to_string("tests/test_data/workbases_only.json")
            .expect("Failed to read test data file");

        // Test deserialization
        let miner_messages: Vec<CkPoolMessage> = serde_json::from_str(&json).unwrap();
        let workbase = match &miner_messages[0] {
            CkPoolMessage::Workbase(workbase) => workbase,
            _ => panic!("Expected Workbase variant"),
        };

        // Verify some fields
        assert_eq!(workbase.workinfoid, 7460801854683742211);
        assert_eq!(workbase.gbt.version, 536870912);
        assert_eq!(workbase.gbt.height, 109);
        assert_eq!(
            workbase.gbt.previousblockhash,
            "00000000e98ac35502140d69c08ea35993b3ac761308b640e045aa648df0e601"
        );
        assert_eq!(workbase.gbt.coinbasevalue, 5000000000);
        assert_eq!(workbase.gbt.diff, 0.001126515290698186);

        // Test serialization back to JSON
        let serialized: String = serde_json::to_string(&workbase).unwrap();

        // Deserialize again to verify round-trip
        let deserialized: MinerWorkbase = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.workinfoid, workbase.workinfoid);
        assert_eq!(deserialized.gbt.version, workbase.gbt.version);
        assert_eq!(deserialized.gbt.height, workbase.gbt.height);
        assert_eq!(
            deserialized.gbt.previousblockhash,
            workbase.gbt.previousblockhash
        );
        assert_eq!(deserialized.gbt.coinbasevalue, workbase.gbt.coinbasevalue);
        assert_eq!(deserialized.gbt.diff, workbase.gbt.diff);
    }
}

#[cfg(test)]
mod miner_share_tests {
    use super::*;
    use crate::test_utils::{simple_miner_share, simple_miner_workbase};
    use rust_decimal_macros::dec;
    use serde_json;

    #[test]
    fn test_miner_work_serialization() {
        let json = r#"{"workinfoid": 7452731920372203525, "clientid": 1, "enonce1": "336c6d67", "nonce2": "0000000000000000", "nonce": "2eb7b82b", "ntime": "676d6caa", "diff": 1.0, "sdiff": 1.9041854952356509, "hash": "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5", "result": true, "errn": 0, "createdate": "1735224559,536904211", "createby": "code", "createcode": "parse_submit", "createinet": "0.0.0.0:3333", "workername": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "username": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "address": "172.19.0.4", "agent": "cpuminer/2.5.1"}"#;

        // Deserialize JSON to MinerWork
        let miner_work: MinerShare = serde_json::from_str(json).unwrap();

        // Verify fields
        assert_eq!(miner_work.workinfoid, 7452731920372203525);
        assert_eq!(miner_work.clientid, 1);
        assert_eq!(miner_work.enonce1, "336c6d67");
        assert_eq!(miner_work.nonce2, "0000000000000000");
        assert_eq!(miner_work.nonce, "2eb7b82b");
        assert_eq!(miner_work.diff, dec!(1.0));
        assert_eq!(miner_work.sdiff, dec!(1.9041854952356509));

        // Serialize back to JSON
        let serialized = serde_json::to_string(&miner_work).unwrap();

        // Deserialize again to verify
        let deserialized: MinerShare = serde_json::from_str(&serialized).unwrap();

        // Verify the round-trip
        assert_eq!(miner_work, deserialized);
    }
    #[test]
    fn test_validate_share() {
        let json = r#"{"workinfoid": 7459044800742817807, "clientid": 1, "enonce1": "336c6d67", "nonce2": "0000000000000000", "nonce": "2eb7b82b", "ntime": "676d6caa", "diff": 1.0, "sdiff": 1.9041854952356509, "hash": "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5", "result": true, "errn": 0, "createdate": "1735224559,536904211", "createby": "code", "createcode": "parse_submit", "createinet": "0.0.0.0:3333", "workername": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "username": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "address": "172.19.0.4", "agent": "cpuminer/2.5.1"}"#;
        let workbase = simple_miner_workbase();

        // Deserialize JSON to MinerWork
        let miner_work: MinerShare = serde_json::from_str(json).unwrap();

        // Test invalid nonce
        let mut invalid_miner_work = miner_work.clone();
        invalid_miner_work.nonce = "invalidhex".to_string();
        let result: Result<(), String> = invalid_miner_work.validate(&workbase);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Invalid nonce hex: Invalid character \'i\' at position 0"
        );

        // Test invalid nonce length
        let mut invalid_miner_work = miner_work.clone();
        invalid_miner_work.nonce = "2eb7b8".to_string();
        let result = invalid_miner_work.validate(&workbase);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid nonce length: 3");
    }

    #[test]
    #[ignore]
    fn test_validate_share_with_workbase() {
        let json = include_str!("../../tests/test_data/validation/workbases_and_shares.json");
        let miner_messages: Vec<CkPoolMessage> = serde_json::from_str(json).unwrap();
        let mut workbases = Vec::new();
        let mut shares = Vec::new();

        for message in miner_messages {
            match message {
                CkPoolMessage::Workbase(workbase) => workbases.push(workbase),
                CkPoolMessage::Share(share) => shares.push(share),
            }
        }

        assert_eq!(workbases.len(), 2);
        assert_eq!(shares.len(), 2);

        let workbase = &workbases[0];
        let share = &shares[0];

        // Validate the share
        let result = share.validate(&workbase);
        assert!(result.is_ok());
    }

    #[test]
    fn test_miner_message_share_deserialization() {
        let json = r#"{"Share": {"workinfoid": 7452731920372203525, "clientid": 1, "enonce1": "336c6d67", "nonce2": "0000000000000000", "nonce": "2eb7b82b", "ntime": "676d6caa", "diff": 1.0, "sdiff": 1.9041854952356509, "hash": "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5", "result": true, "errn": 0, "createdate": "1735224559,536904211", "createby": "code", "createcode": "parse_submit", "createinet": "0.0.0.0:3333", "workername": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "username": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "address": "172.19.0.4", "agent": "cpuminer/2.5.1"}}"#;

        // Deserialize JSON to MinerMessage
        let miner_message: CkPoolMessage = serde_json::from_str(json).unwrap();

        // Verify it's a Share variant and check fields
        match &miner_message {
            CkPoolMessage::Share(share) => {
                assert_eq!(share.workinfoid, 7452731920372203525);
                assert_eq!(share.clientid, 1);
                assert_eq!(share.enonce1, "336c6d67");
                assert_eq!(share.nonce2, "0000000000000000");
                assert_eq!(share.nonce, "2eb7b82b");
                assert_eq!(share.diff, dec!(1.0));
                assert_eq!(share.sdiff, dec!(1.9041854952356509));
            }
            _ => panic!("Expected Share variant"),
        }

        let miner_message_share = match &miner_message {
            CkPoolMessage::Share(share) => share,
            _ => panic!("Expected Share variant"),
        };

        // Serialize back to JSON
        let serialized = serde_json::to_string(&miner_message).unwrap();

        // Deserialize again to verify
        let deserialized: CkPoolMessage = serde_json::from_str(&serialized).unwrap();

        let deserialized_share = match &deserialized {
            CkPoolMessage::Share(share) => share,
            _ => panic!("Expected Share variant"),
        };

        // Verify the round-trip
        assert_eq!(
            miner_message_share.workinfoid,
            deserialized_share.workinfoid
        );
        assert_eq!(miner_message_share.clientid, deserialized_share.clientid);
        assert_eq!(miner_message_share.enonce1, deserialized_share.enonce1);
        assert_eq!(miner_message_share.nonce2, deserialized_share.nonce2);
        assert_eq!(miner_message_share.nonce, deserialized_share.nonce);
        assert_eq!(miner_message_share.ntime, deserialized_share.ntime);
        assert_eq!(miner_message_share.diff, deserialized_share.diff);
        assert_eq!(miner_message_share.sdiff, deserialized_share.sdiff);
    }

    // {"Workbase": Object {"gbt": Object {"bbversion": String("20000000"), "bits": String("1e0377ae"), "capabilities": Array [String("proposal")], "coinbaseaux": Object {}, "coinbasevalue": Number(5000000000), "curtime": Number(1737100205), "default_witness_commitment": String("6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"), "diff": Number(0.001126515290698186), "height": Number(99), "longpollid": String("00000000eefbb1ae2a6ca9e826209f19d9a9f00c1ea443fa062debf89a32fcfc1"), "mintime": Number(1736687181), "mutable": Array [String("time"), String("transactions"), String("prevblock")], "nbit": String("1e0377ae"), "noncerange": String("00000000ffffffff"), "ntime": String("678a0bad"), "previousblockhash": String("00000000eefbb1ae2a6ca9e826209f19d9a9f00c1ea443fa062debf89a32fcfc"), "rules": Array [String("csv"), String("!segwit"), String("!signet"), String("taproot")], "signet_challenge": String("51"), "sigoplimit": Number(80000), "sizelimit": Number(4000000), "target": String("00000377ae000000000000000000000000000000000000000000000000000000"), "transactions": Array [], "vbavailable": Object {}, "vbrequired": Number(0), "version": Number(536870912), "weightlimit": Number(4000000)}, "workinfoid": Number(7460787496608071691)}}
    #[test]
    fn test_miner_message_workbase_deserialization() {
        let json_str = include_str!("../../tests/test_data/simple_miner_workbase.json");
        let workbase: MinerWorkbase = serde_json::from_str(&json_str).unwrap();

        // Verify it's a Workbase variant and check fields
        assert_eq!(workbase.workinfoid, 7459044800742817807);
        assert_eq!(workbase.gbt.height, 98);
        assert_eq!(workbase.gbt.bits, "1e0377ae");
        assert_eq!(
            workbase.gbt.previousblockhash,
            "00000000790ba17d9c06acf8749166014eb1499c8ea6dd598060dbec7eeae808"
        );

        // Serialize back to JSON
        let serialized = serde_json::to_string(&workbase).unwrap();

        // Deserialize again to verify
        let deserialized: MinerWorkbase = serde_json::from_str(&serialized).unwrap();

        // Verify the round-trip
        assert_eq!(workbase, deserialized);
    }

    #[test]
    fn test_miner_share_serialized_size() {
        let share = simple_miner_share(None, None, None, None);
        let message = CkPoolMessage::Share(share);

        // Serialize to JSON
        let serialized = serde_json::to_string(&message).unwrap();

        // Print and verify the size
        println!("Serialized share size: {} bytes", serialized.len());
        println!("Serialized share: {}", serialized);

        // The size should be reasonable for network transmission
        assert_eq!(serialized.len(), 316);
    }

    #[test_log::test(test)]
    fn test_workbase_coinbase_deserialization() {
        // Read test data file
        let test_data =
            std::fs::read_to_string("tests/test_data/validation/workbases_and_shares.json")
                .unwrap();
        let messages: Vec<CkPoolMessage> = serde_json::from_str(&test_data).unwrap();

        // Group workbases and shares
        let mut workbase_share_pairs = Vec::new();
        let mut current_workbase: Option<MinerWorkbase> = None;

        for message in messages {
            match message {
                CkPoolMessage::Workbase(workbase) => {
                    current_workbase = Some(workbase);
                }
                CkPoolMessage::Share(share) => {
                    if let Some(workbase) = current_workbase.clone() {
                        workbase_share_pairs.push((workbase, share));
                    }
                }
            }
        }

        // Validate each workbase-share pair
        for (workbase, share) in workbase_share_pairs {
            let coinbase = validate_coinbase(&workbase, &share).unwrap();
            assert!(coinbase.is_coinbase());
        }
    }
}

fn validate_coinbase(
    workbase: &MinerWorkbase,
    share: &MinerShare,
) -> Result<bitcoin::Transaction, Box<dyn std::error::Error>> {
    use hex::FromHex;

    let coinb1 = &workbase.coinb1;
    let coinb2 = &workbase.coinb2;
    let enonce1 = &share.enonce1;
    let nonce2 = &share.nonce2;
    let txnbinlen = &workbase.txnbinlen;
    let txnbin = &workbase.txnbin;
    let coinb3 = &workbase.coinb3;

    let complete_tx = format!(
        "{}{}{}{}{}{}{}",
        coinb1, enonce1, nonce2, coinb2, txnbinlen, txnbin, coinb3
    );

    // Try to deserialize
    let tx_bytes = Vec::from_hex(&complete_tx).unwrap();
    bitcoin::Transaction::consensus_decode(&mut std::io::Cursor::new(tx_bytes))
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}
