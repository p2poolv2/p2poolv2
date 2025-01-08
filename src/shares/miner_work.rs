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

use serde::{Serialize, Deserialize};
use rust_decimal::Decimal;

/// Represents the work done by a miner.
/// We use Decimal for the diff and sdiff fields to avoid floating point precision issues.
#[derive(Clone, PartialEq, Serialize, Deserialize, Default, Debug)]
pub struct MinerWork {
    pub workinfoid: u64,
    pub clientid: u64,
    pub enonce1: String,
    pub nonce2: String,
    pub nonce: String,
    pub ntime: String,
    pub diff: Decimal,
    pub sdiff: Decimal,
    pub hash: String,
    pub result: bool,
    pub errn: i32,
    pub createdate: String,
    pub createby: String,
    pub createcode: String,
    pub createinet: String,
    pub workername: String,
    pub username: String,
    pub address: String,
    pub agent: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use serde_json;

    #[test]
    fn test_miner_work_serialization() {
        let json = r#"{"workinfoid": 7452731920372203525, "clientid": 1, "enonce1": "336c6d67", "nonce2": "0000000000000000", "nonce": "2eb7b82b", "ntime": "676d6caa", "diff": 1.0, "sdiff": 1.9041854952356509, "hash": "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb5", "result": true, "errn": 0, "createdate": "1735224559,536904211", "createby": "code", "createcode": "parse_submit", "createinet": "0.0.0.0:3333", "workername": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "username": "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d", "address": "172.19.0.4", "agent": "cpuminer/2.5.1"}"#;

        // Deserialize JSON to MinerWork
        let miner_work: MinerWork = serde_json::from_str(json).unwrap();

        // Verify fields
        assert_eq!(miner_work.workinfoid, 7452731920372203525);
        assert_eq!(miner_work.clientid, 1);
        assert_eq!(miner_work.enonce1, "336c6d67");
        assert_eq!(miner_work.nonce2, "0000000000000000");
        assert_eq!(miner_work.nonce, "2eb7b82b");
        assert_eq!(miner_work.diff, dec!(1.0));
        assert_eq!(miner_work.sdiff, dec!(1.9041854952356509));
        assert_eq!(miner_work.result, true);
        assert_eq!(miner_work.agent, "cpuminer/2.5.1");

        // Serialize back to JSON
        let serialized = serde_json::to_string(&miner_work).unwrap();
        
        // Deserialize again to verify
        let deserialized: MinerWork = serde_json::from_str(&serialized).unwrap();
        
        // Verify the round-trip
        assert_eq!(miner_work, deserialized);
    }
}
