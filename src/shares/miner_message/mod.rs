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

pub mod builders;

use crate::utils::serde_support::time::{deserialize_time, serialize_time};
use bitcoin::absolute::Time;
use hex;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub enum CkPoolMessage {
    Share(MinerShare),
    Workbase(MinerWorkbase),
    UserWorkbase(UserWorkbase),
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
    pub fn validate(
        &self,
        workbase: &MinerWorkbase,
        user_workbase: &UserWorkbase,
    ) -> Result<bool, String> {
        let coinbase = builders::build_coinbase_from_share(workbase, user_workbase, &self)
            .map_err(|e| format!("Failed to build coinbase: {}", e))?;
        let coinbase_txid = coinbase.compute_txid();
        let txids = workbase
            .txns
            .iter()
            .map(|tx| bitcoin::Txid::from_str(&tx.txid))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse txid: {}", e))?;
        let mut all_txids = vec![coinbase_txid];
        all_txids.extend(&txids);

        let merkle_root = builders::compute_merkle_root_from_txids(&all_txids)
            .ok_or_else(|| "Failed to compute merkle root".to_string())?;
        let header = builders::build_bitcoin_header(workbase, self, merkle_root)
            .map_err(|e| format!("Failed to build header: {}", e))?;
        let block = builders::build_bitcoin_block(workbase, user_workbase, self)
            .map_err(|e| format!("Failed to build block: {}", e))?;

        let compact_target =
            bitcoin::pow::CompactTarget::from_unprefixed_hex(&user_workbase.params.nbit).unwrap();
        let required_target = bitcoin::Target::from_compact(compact_target);
        // Validate proof of work
        if header.validate_pow(required_target).is_err() {
            return Err("Invalid proof of work".to_string());
        }

        // Check merkle root
        if !block.check_merkle_root() {
            return Err("Invalid merkle root".to_string());
        }

        // Check witness commitment
        if !block.check_witness_commitment() {
            return Err("Invalid witness commitment".to_string());
        }

        Ok(true)
    }
}

#[cfg(test)]
use mockall::mock;

#[cfg(test)]
mock! {
    pub MinerShare {
        pub fn validate(&self, workbase: &MinerWorkbase) -> Result<bool, String>;
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
    // The bitcoin block header as a hex string without merkle root and nonce
    pub header: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(into = "(String, String, String, String, Vec<String>, String, String, String, bool)")]
#[serde(from = "(String, String, String, String, Vec<String>, String, String, String, bool)")]
pub struct UserWorkbaseParams {
    pub id: String,
    pub prevhash: String,
    pub coinb1: String,
    pub coinb2: String,
    pub merkles: Vec<String>,
    pub version: String,
    pub nbit: String,
    pub ntime: String,
    pub clean_jobs: bool,
}

impl From<UserWorkbaseParams>
    for (
        String,
        String,
        String,
        String,
        Vec<String>,
        String,
        String,
        String,
        bool,
    )
{
    fn from(params: UserWorkbaseParams) -> Self {
        (
            params.id,
            params.prevhash,
            params.coinb1,
            params.coinb2,
            params.merkles,
            params.version,
            params.nbit,
            params.ntime,
            params.clean_jobs,
        )
    }
}

impl
    From<(
        String,
        String,
        String,
        String,
        Vec<String>,
        String,
        String,
        String,
        bool,
    )> for UserWorkbaseParams
{
    fn from(
        (id, prevhash, coinb1, coinb2, merkles, version, nbit, ntime, clean_jobs): (
            String,
            String,
            String,
            String,
            Vec<String>,
            String,
            String,
            String,
            bool,
        ),
    ) -> Self {
        Self {
            id,
            prevhash,
            coinb1,
            coinb2,
            merkles,
            version,
            nbit,
            ntime,
            clean_jobs,
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct UserWorkbase {
    pub params: UserWorkbaseParams,
    pub id: Option<String>,
    pub method: String,
    pub workinfoid: u64,
}

/// Represents the getblocktemplate used in ckpool as workbase
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Gbt {
    pub capabilities: Vec<String>,
    pub version: i32,
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
    fn test_userworkbase_deserialization() {
        let json = std::fs::read_to_string("tests/test_data/validation/userworkbases.json")
            .expect("Failed to read test data file");

        // Test deserialization
        let messages: Vec<CkPoolMessage> = serde_json::from_str(&json).unwrap();
        let userworkbase = match &messages[0] {
            CkPoolMessage::UserWorkbase(userworkbase) => userworkbase,
            _ => panic!("Expected UserWorkbase variant"),
        };

        // Verify fields
        assert_eq!(userworkbase.workinfoid, 7473434392883363843);
        assert_eq!(userworkbase.method, "mining.notify");
        assert_eq!(userworkbase.id, None);

        // Verify params
        let params = &userworkbase.params;
        assert_eq!(params.id, "67b6f8fc00000003");
        assert_eq!(
            params.prevhash,
            "6d600f568f665af26301fcafa53326454b9db355ff5d87f9863a956300000000"
        );
        assert_eq!(params.coinb1, "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2c017b000438f9b667049c0fc52d0c");
        assert_eq!(params.coinb2, "0a636b706f6f6c0a2f7032706f6f6c76322fffffffff0300111024010000001600148f1b6f0d5a0422afad259ec03977bdf2c74a037600e1f50500000000160014a248cf2f99f449511b22bab1a3d001719f84cd090000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000");
        assert!(params.merkles.is_empty());
        assert_eq!(params.version, "20000000");
        assert_eq!(params.nbit, "1e0377ae");
        assert_eq!(params.ntime, "67b6f938");
        assert_eq!(params.clean_jobs, false);

        // Test serialization back to JSON
        let serialized = serde_json::to_string(&userworkbase).unwrap();

        // Deserialize again to verify round-trip
        let deserialized: UserWorkbase = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.workinfoid, userworkbase.workinfoid);
        assert_eq!(deserialized.method, userworkbase.method);
        assert_eq!(deserialized.params, userworkbase.params);
    }

    #[test]
    fn test_add_workbase() {
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
    use crate::test_utils::{
        load_valid_workbases_userworkbases_and_shares, simple_miner_share, simple_miner_workbase,
    };
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
        let (workbases, userworkbases, shares) = load_valid_workbases_userworkbases_and_shares();

        // Test invalid nonce
        let mut invalid_miner_work = shares[0].clone();
        invalid_miner_work.nonce = "invalidhex".to_string();
        let result = invalid_miner_work.validate(&workbases[0], &userworkbases[0]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Failed to build header: invalid digit found in string"
        );

        // Test invalid nonce
        let mut invalid_miner_work = shares[0].clone();
        invalid_miner_work.nonce = "2eb7b8".to_string();
        let result = invalid_miner_work.validate(&workbases[0], &userworkbases[0]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid proof of work");
    }

    #[test]
    #[ignore]
    fn test_validate_share_with_workbase() {
        let (workbases, userworkbases, shares) = load_valid_workbases_userworkbases_and_shares();

        let workbase = &workbases[0];
        let userworkbase = &userworkbases[0];
        let share = &shares[0];

        // Validate the share
        let result = share.validate(&workbase, &userworkbase);
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
        let json_str = include_str!("../../../tests/test_data/simple_miner_workbase.json");
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

        // The size should be reasonable for network transmission
        assert_eq!(serialized.len(), 316);
    }

    #[test_log::test(test)]
    fn test_workbase_coinbase_deserialization() {
        let (workbases, userworkbases, shares) = load_valid_workbases_userworkbases_and_shares();

        // Validate each workbase-share pair
        for ((workbase, userworkbase), share) in workbases
            .iter()
            .zip(userworkbases.iter())
            .zip(shares.iter())
        {
            let coinbase =
                builders::build_coinbase_from_share(&workbase, &userworkbase, &share).unwrap();
            assert!(coinbase.is_coinbase());
        }
    }
}
