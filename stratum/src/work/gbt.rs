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

// /// Start a task to fetch block templates from bitcoind
// pub async fn start_gbt<B: BitcoindRpc + Sync + Send + 'static>(
//     url: String,
//     username: String,
//     password: String,
//     result_tx: tokio::sync::mpsc::Sender<BlockTemplate>,
// ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//     tokio::spawn(async move {
//         let bitcoind = match B::new(url, username, password) {
//             Ok(bitcoind) => bitcoind,
//             Err(e) => {
//                 info!("Failed to connect to bitcoind: {}", e);
//                 return;
//             }
//         };
//         loop {
//             match get_block_template(&bitcoind).await {
//                 Ok(template) => {
//                     debug!("Block template: {:?}", template);
//                     if result_tx.send(template).await.is_err() {
//                         info!("Failed to send block template to channel");
//                     }
//                 }
//                 Err(e) => {
//                     info!("Error getting block template: {}", e);
//                 }
//             };
//         }
//     })
//     .await;
//     Err(Box::new(WorkError {
//         message: "Failed to start GBT".to_string(),
//     }))
// }

#[cfg(test)]
mod gbt_load_tests {
    use super::*;
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
    #[test_log::test]
    fn test_compute_merkle_branches_single_txid() {
        // Only one txid, branch should be just that txid
        let txid = sha256d::Hash::hash(&[1u8; 32]);
        let branches = compute_merkle_branches(vec![txid]);
        assert_eq!(branches, vec![txid]);
    }

    #[test]
    fn test_compute_merkle_branches_two_txids() {
        let txid1 = sha256d::Hash::hash(&[1u8; 32]);
        let txid2 = sha256d::Hash::hash(&[2u8; 32]);
        let expected_hash = sha256d::Hash::hash(&[txid2, txid2].concat());
        let branches = compute_merkle_branches(vec![txid1, txid2]);
        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0], txid1);
        assert_eq!(branches[1], expected_hash);
    }

    #[test]
    fn test_compute_merkle_branches_three_txids() {
        let txid1 = sha256d::Hash::hash(&[1u8; 32]);
        let txid2 = sha256d::Hash::hash(&[2u8; 32]);
        let txid3 = sha256d::Hash::hash(&[3u8; 32]);

        let h23 = sha256d::Hash::hash(&[txid2, txid3].concat());
        let branches = compute_merkle_branches(vec![txid1, txid2, txid3]);

        assert_eq!(branches[0], txid1);
        assert_eq!(branches[1], h23);
        assert_eq!(branches.len(), 2);
    }

    #[test]
    fn test_compute_merkle_branches_four_txids() {
        let txid1 = sha256d::Hash::hash(&[1u8; 32]);
        let txid2 = sha256d::Hash::hash(&[2u8; 32]);
        let txid3 = sha256d::Hash::hash(&[3u8; 32]);
        let txid4 = sha256d::Hash::hash(&[4u8; 32]);

        let h23 = sha256d::Hash::hash(&[txid2, txid3].concat());
        let h44 = sha256d::Hash::hash(&[txid4, txid4].concat());
        let h4444 = sha256d::Hash::hash(&[h44, h44].concat());

        let branches = compute_merkle_branches(vec![txid1, txid2, txid3, txid4]);
        assert_eq!(branches[0], txid1);
        assert_eq!(branches[1], h23);
        assert_eq!(branches[2], h4444);
        assert_eq!(branches.len(), 3);
    }
}
