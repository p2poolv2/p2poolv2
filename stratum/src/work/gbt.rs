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

use crate::work::error::WorkError;
use bitcoin::hashes::{sha256d, Hash};
use bitcoindrpc::BitcoindRpc;
use serde::{Deserialize, Serialize};

/// Struct representing the getblocktemplate response from Bitcoin Core
#[derive(Debug, Deserialize, Serialize)]
pub struct BlockTemplate {
    pub version: u32,
    pub rules: Vec<String>,
    pub vbavailable: std::collections::HashMap<String, i32>,
    pub vbrequired: u32,
    pub previousblockhash: String,
    pub transactions: Vec<TemplateTransaction>,
    pub coinbaseaux: std::collections::HashMap<String, String>,
    pub coinbasevalue: u64,
    pub longpollid: String,
    pub target: String,
    pub mintime: u64,
    pub mutable: Vec<String>,
    pub noncerange: String,
    pub sigoplimit: u32,
    pub sizelimit: u32,
    pub weightlimit: u32,
    pub curtime: u64,
    pub bits: String,
    pub height: u32,
    #[serde(
        rename = "default_witness_commitment",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_witness_commitment: Option<String>,
}

/// Transaction data in the block template
#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateTransaction {
    pub data: String,
    pub txid: String,
    pub hash: String,
    pub depends: Vec<u32>,
    pub fee: u64,
    pub sigops: u32,
    pub weight: u32,
}

/// Compute merkle branches for the transactions in the block template
/// Uses private compute_merkle_branches after parsing the txids from the template
pub fn build_merkle_branches_for_template(template: &BlockTemplate) -> Vec<sha256d::Hash> {
    let txids = template
        .transactions
        .iter()
        .map(|tx| tx.txid.parse().unwrap())
        .collect();
    compute_merkle_branches(txids)
}

/// Compute merkle branch from coinbase transaction and BlockTemplate's transactions
fn compute_merkle_branches(input_txids: Vec<sha256d::Hash>) -> Vec<sha256d::Hash> {
    let mut txids = input_txids.clone();
    let mut merkle_branches = Vec::new();
    while !txids.is_empty() {
        merkle_branches.push(txids[0]);
        let mut new_txids = Vec::new();
        for i in (1..txids.len()).step_by(2) {
            let left = txids[i];
            let right = if i + 1 < txids.len() {
                txids[i + 1]
            } else {
                left
            };
            let hash = sha256d::Hash::hash(&[left, right].concat());
            new_txids.push(hash);
        }
        txids = new_txids;
    }
    merkle_branches
}

/// Get a new blocktemplate from the bitcoind server
/// Parse the received JSON into a BlockTemplate struct and return it.
async fn get_block_template<R: BitcoindRpc>(
    bitcoind: &R,
) -> Result<BlockTemplate, Box<dyn std::error::Error + Send + Sync>> {
    match bitcoind.getblocktemplate(bitcoin::Network::Signet).await {
        Ok(blocktemplate_json) => {
            match serde_json::from_str::<BlockTemplate>(blocktemplate_json.as_str()) {
                Ok(template) => Ok(template),
                Err(e) => Err(Box::new(WorkError {
                    message: format!("Failed to parse block template: {}", e),
                })),
            }
        }
        Err(e) => Err(Box::new(WorkError {
            message: format!("Failed to get block template: {}", e),
        })),
    }
}

#[cfg(test)]
mod gbt_load_tests {
    use super::*;
    use bitcoin::hex::FromHex;
    use bitcoindrpc::MockBitcoindRpc;

    #[tokio::test]
    async fn test_get_block_template() {
        let template = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/gbt/signet/gbt-no-transactions.json"),
        )
        .expect("Failed to read test fixture");
        let mut mock_rpc = MockBitcoindRpc::default();
        mock_rpc
            .expect_getblocktemplate()
            .with(mockall::predicate::eq(bitcoin::Network::Signet))
            .returning(move |_| {
                let template = template.clone();
                Box::pin(async move { Ok(template) })
            });

        let result = get_block_template(&mock_rpc).await;
        assert!(result.is_ok());
        let template = result.unwrap();
        assert_eq!(template.version, 536870912);
        assert_eq!(template.rules.len(), 4);
        assert_eq!(template.rules[1], "!segwit");
        assert_eq!(
            template.previousblockhash,
            "000000006648c58af2ea07d976804c4cbd40377e566af5694f14ecac2b0065c1"
        );
        assert_eq!(
            template.default_witness_commitment,
            Some(
                "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
                    .to_string()
            )
        )
    }

    // The test data comes from tests/test_data/gbt/regtest/ckpool/one-txn dir
    #[test_log::test]
    fn test_compute_merkle_branches_single_txid() {
        // Only one txid, branch should be just that txid
        let txid: sha256d::Hash =
            "2305d23e3d6a9f55189723e0dfc653908455a9162b263a0b7b584711cff8cdfe"
                .parse()
                .unwrap();
        let branches = compute_merkle_branches(vec![txid]);
        assert_eq!(branches, vec![txid]);
    }

    // The test data comes from tests/test_data/gbt/regtest/ckpool/two-txns dir
    #[test]
    fn test_compute_merkle_branches_two_txids() {
        let txid1: sha256d::Hash =
            "9a1644beab4dfaccc9bb3cbd5008b0581dd314102fcd79b69a2c724a8010d706"
                .parse()
                .unwrap();
        let txid2: sha256d::Hash =
            "3bca24fa1c1bc8cfcf77dfd974bb5c80ea865caa828c2e43f86cea862d5d6e40"
                .parse()
                .unwrap();

        let expected_hash = sha256d::Hash::hash(&[txid2, txid2].concat());
        let branches = compute_merkle_branches(vec![txid1, txid2]);
        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0], txid1);
        assert_eq!(branches[1], expected_hash);

        // The expected merkle branches from ckpool's notify messages
        let v1 = Vec::from_hex("06d710804a722c9ab679cd2f1014d31d58b00850bd3cbbc9ccfa4dabbe44169a")
            .unwrap();
        let v2 = Vec::from_hex("dfa3f22130ce2941d79b5f6c35d15f15688910e49b4d7e460f07cb44c925ca49")
            .unwrap();
        let expected: Vec<sha256d::Hash> = vec![
            sha256d::Hash::from_slice(&v1).unwrap(),
            sha256d::Hash::from_slice(&v2).unwrap(),
        ];
        assert_eq!(branches, expected);
    }

    // The test data comes from tests/test_data/gbt/regtest/ckpool/three-txns dir
    #[test]
    fn test_compute_merkle_branches_three_txids() {
        let txid1: sha256d::Hash =
            "4193df037a4d8ffb9815f2fdae19abab69821f06625004a1e84d8df73cc0c044"
                .parse()
                .unwrap();
        let txid2: sha256d::Hash =
            "082af095391dbb4d8918765f41524e010ee3838adf3b3b13f280a6c83cad7776"
                .parse()
                .unwrap();
        let txid3: sha256d::Hash =
            "58dd52c691e92e6e9da0be3146dfdc87c2c7c1ab6e64476f26427c6d771de6a5"
                .parse()
                .unwrap();

        let h23 = sha256d::Hash::hash(&[txid2, txid3].concat());
        let branches = compute_merkle_branches(vec![txid1, txid2, txid3]);

        assert_eq!(branches[0], txid1);
        assert_eq!(branches[1], h23);
        assert_eq!(branches.len(), 2);

        // The expected merkle branches from ckpool's notify messages
        let v1 = Vec::from_hex("44c0c03cf78d4de8a1045062061f8269abab19aefdf21598fb8f4d7a03df9341")
            .unwrap();
        let v2 = Vec::from_hex("0dce56f68943df6531358e75bcad1e49e2456413cfd03244beaabc8cc9b69ee3")
            .unwrap();
        let expected: Vec<sha256d::Hash> = vec![
            sha256d::Hash::from_slice(&v1).unwrap(),
            sha256d::Hash::from_slice(&v2).unwrap(),
        ];
        assert_eq!(branches, expected);
    }

    // The test data comes from tests/test_data/gbt/regtest/ckpool/three-txns dir
    #[test]
    fn test_compute_merkle_branches_four_txids() {
        let txid1: sha256d::Hash =
            "19d9fe2c24a7b88b4d0455c9f42ce16eec881a9fc2cf1194a554129f8e297c27"
                .parse()
                .unwrap();
        let txid2: sha256d::Hash =
            "c3e8a4a3405cafc0ac48a1c602cf6962c74f180dccbd7a423a9216497dcb474e"
                .parse()
                .unwrap();
        let txid3: sha256d::Hash =
            "1b991d93da9c481637d7285ec378d4b1fd6b1ccb06fed594951f3705b3869ddb"
                .parse()
                .unwrap();
        let txid4: sha256d::Hash =
            "13a0ba57fdd05ce8b89950f792d8849ee636831a77d9f1eb1fda38e68991a2f0"
                .parse()
                .unwrap();

        let h23 = sha256d::Hash::hash(&[txid2, txid3].concat());
        let h44 = sha256d::Hash::hash(&[txid4, txid4].concat());
        let h4444 = sha256d::Hash::hash(&[h44, h44].concat());

        let branches = compute_merkle_branches(vec![txid1, txid2, txid3, txid4]);
        assert_eq!(branches[0], txid1);
        assert_eq!(branches[1], h23);
        assert_eq!(branches[2], h4444);
        assert_eq!(branches.len(), 3);

        // The expected merkle branches from ckpool's notify messages
        let v1 = Vec::from_hex("277c298e9f1254a59411cfc29f1a88ec6ee12cf4c955044d8bb8a7242cfed919")
            .unwrap();
        let v2 = Vec::from_hex("20838512651774fd1482b92f7d55e14103e773b92721873a29bb06846f297683")
            .unwrap();
        let v3 = Vec::from_hex("50c833466187becdc8e2f069352e7be34da07d653793093861c913eef295285c")
            .unwrap();
        let expected: Vec<sha256d::Hash> = vec![
            sha256d::Hash::from_slice(&v1).unwrap(),
            sha256d::Hash::from_slice(&v2).unwrap(),
            sha256d::Hash::from_slice(&v3).unwrap(),
        ];
        assert_eq!(branches, expected);
    }
}
