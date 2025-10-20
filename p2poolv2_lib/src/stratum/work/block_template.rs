// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Transaction data in the block template
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TemplateTransaction {
    pub data: String,
    pub txid: String,
    pub hash: String,
    pub depends: Vec<u32>,
    pub fee: u64,
    pub sigops: u32,
    pub weight: u32,
}

/// Struct representing the getblocktemplate response from Bitcoin Core
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlockTemplate<T = TemplateTransaction> {
    pub version: i32,
    pub rules: Vec<String>,
    pub vbavailable: std::collections::HashMap<String, i32>,
    pub vbrequired: u32,
    pub previousblockhash: String,
    pub transactions: Vec<T>,
    pub coinbaseaux: HashMap<String, String>,
    pub coinbasevalue: u64,
    pub longpollid: String,
    pub target: String,
    pub mintime: u32,
    pub mutable: Vec<String>,
    pub noncerange: String,
    pub sigoplimit: u32,
    pub sizelimit: u32,
    pub weightlimit: u32,
    pub curtime: u32,
    pub bits: String,
    pub height: u32,
    #[serde(
        rename = "default_witness_commitment",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_witness_commitment: Option<String>,
}

impl From<&TemplateTransaction> for bitcoin::Transaction {
    fn from(tx: &TemplateTransaction) -> Self {
        let bytes = hex::decode(&tx.data).expect("Failed to decode transaction hex");
        bitcoin::consensus::deserialize(&bytes)
            .expect("Failed to deserialize transaction from slice")
    }
}

impl From<TemplateTransaction> for bitcoin::Transaction {
    fn from(tx: TemplateTransaction) -> Self {
        bitcoin::Transaction::from(&tx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_template_transaction_conversion() {
        let tx_data = TemplateTransaction {
            data: "02000000000101d6c83b002c07d56399a5e0c887ddc7b74071b301a3ffa630c15754c63d8bee750000000000fdffffff02ac78f62901000000160014aecdd0cfae0829ee25e172cc8a94b2aa702869a040420f0000000000160014230a8d012b7cfce1a3118c617d6c50ce9f7482d602473044022037aede936712b0e32aaeba0413833f66929b1bff3726414294b1b140cc93595402204aa43cce61d2c8a9e8131aa335d884212bc2d63f74fea0c13c8ade3640f4b291012103555f1c1815b0a5a5ce7eeac3b7da8923e2c440ed94fc40e9d2685ed45f5335b5bb030000".to_string(),
            txid: "74d7b9bf9f51dd7447e117b6a835a20b6f7d5d807285d1435da37574563ca525".to_string(),
            hash: "000002d6ed0236ae93ae9affa9d02f7a4ebf21430a202a86a7ef4ae4f95bad00".to_string(),
            depends: vec![],
            fee: 5000,
            sigops: 4,
            weight: 892,
        };

        let bitcoin_tx: bitcoin::Transaction = tx_data.into();
        assert_eq!(
            bitcoin_tx.compute_txid().to_string(),
            "74d7b9bf9f51dd7447e117b6a835a20b6f7d5d807285d1435da37574563ca525"
        );
    }

    #[test]
    fn test_load_transactions_from_json() {
        // Load the test JSON file
        let json_path =
            Path::new("../tests/test_data/validation/stratum/gbt_with_transactions.json");
        let json_content = fs::read_to_string(json_path).expect("Failed to read test JSON file");

        // Parse the JSON into BlockTemplate
        let block_template: BlockTemplate =
            serde_json::from_str(&json_content).expect("Failed to parse JSON into BlockTemplate");

        // Verify we have transactions
        assert!(!block_template.transactions.is_empty());

        // Take the first transaction for detailed testing
        let first_tx = &block_template.transactions[0];

        // Convert to Bitcoin Transaction
        let btc_tx: bitcoin::Transaction = first_tx.clone().into();

        // Verify transaction properties
        assert_eq!(btc_tx.compute_txid().to_string(), first_tx.txid);

        assert_eq!(btc_tx.input.len(), 1);
        assert_eq!(btc_tx.output.len(), 2);
        assert_eq!(btc_tx.input[0].previous_output.vout, 0);
        assert_eq!(
            btc_tx.input[0].previous_output.txid.to_string(),
            "75ee8b3dc65457c130a6ffa301b37140b7c7dd87c8e0a59963d5072c003bc8d6"
        );
        assert_eq!(
            btc_tx.output[0].value,
            bitcoin::Amount::from_btc(49.98985900).unwrap()
        );
    }
}
