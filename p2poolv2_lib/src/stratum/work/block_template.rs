// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::shares::coinbaseaux_flags::CoinbaseAuxFlags;
use crate::stratum::work::error::WorkError;
use bitcoin::block::Header;
use bitcoin::consensus::encode::VarInt;
use bitcoin::hashes::Hash;
use bitcoin::script::PushBytesBuf;
use bitcoin::{BlockHash, CompactTarget, Target, Transaction, Txid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Transaction data in the block template
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct TemplateTransaction {
    pub data: String,
    pub txid: String,
    #[serde(default)]
    pub hash: String,
    /// Indexes of earlier template transactions this one spends. BCHN omits
    /// the field: its templates are in canonical order, not dependency order.
    #[serde(default)]
    pub depends: Vec<u32>,
    pub fee: u64,
    pub sigops: u32,
    #[serde(default)]
    pub weight: u32,
}

/// Template fields shared by Bitcoin Core and BCHN. BCH has no block weight.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BlockTemplate<T = TemplateTransaction> {
    pub version: i32,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub vbavailable: std::collections::HashMap<String, i32>,
    #[serde(default)]
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
    #[serde(default)]
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

impl TryFrom<&TemplateTransaction> for Transaction {
    type Error = WorkError;

    fn try_from(transaction: &TemplateTransaction) -> Result<Self, Self::Error> {
        let bytes = hex::decode(&transaction.data).map_err(|error| WorkError {
            message: format!("Invalid template transaction hex: {error}"),
        })?;
        bitcoin::consensus::deserialize(&bytes).map_err(|error| WorkError {
            message: format!("Invalid template transaction: {error}"),
        })
    }
}

impl TryFrom<TemplateTransaction> for Transaction {
    type Error = WorkError;

    fn try_from(transaction: TemplateTransaction) -> Result<Self, Self::Error> {
        Transaction::try_from(&transaction)
    }
}

impl BlockTemplate {
    /// Decode template transactions, returning malformed node data as an error.
    pub fn decode_transactions(&self) -> Result<Vec<Transaction>, WorkError> {
        self.transactions
            .iter()
            .map(Transaction::try_from)
            .collect()
    }

    /// Check BCH template data before computing merkle branches or issuing jobs.
    /// CTOR is checked in displayed transaction ID order; the coinbase is separate.
    pub fn validate_bch(&self) -> Result<(), WorkError> {
        let invalid = |message: &str| WorkError {
            message: format!("Invalid BCH template: {message}"),
        };
        self.previousblockhash
            .parse::<BlockHash>()
            .map_err(|_| invalid("invalid previous block hash"))?;
        let bits = u32::from_str_radix(&self.bits, 16)
            .map(CompactTarget::from_consensus)
            .map_err(|_| invalid("invalid compact target"))?;
        let target = Target::from_compact(bits);
        let target_bytes: [u8; 32] = hex::decode(&self.target)
            .map_err(|_| invalid("invalid target hex"))?
            .try_into()
            .map_err(|_| invalid("target must be 32 bytes"))?;
        if self.bits.len() != 8
            || target == Target::ZERO
            || bits.to_consensus() & 0x00800000 != 0
            || target.to_compact_lossy() != bits
            || target.to_be_bytes() != target_bytes
        {
            return Err(invalid("target and compact bits disagree or are invalid"));
        }
        if self.curtime < self.mintime || self.sizelimit < 81 || self.sigoplimit == 0 {
            return Err(invalid("invalid timestamp or block limits"));
        }
        if self.coinbasevalue > bitcoin::Amount::MAX_MONEY.to_sat() {
            return Err(invalid("coinbase value exceeds maximum money"));
        }
        if self.default_witness_commitment.is_some()
            || self.weightlimit != 0
            || self.rules.iter().any(|rule| {
                matches!(
                    rule.trim_start_matches('!'),
                    "segwit" | "signet" | "taproot"
                )
            })
        {
            return Err(invalid("Bitcoin-only consensus fields"));
        }
        let mut previous_txid: Option<Txid> = None;
        let mut transaction_bytes = 0usize;
        for template_transaction in &self.transactions {
            let transaction = Transaction::try_from(template_transaction)?;
            let txid = transaction.compute_txid();
            if template_transaction.txid.parse::<Txid>().ok() != Some(txid)
                || (!template_transaction.hash.is_empty()
                    && template_transaction.hash.parse::<Txid>().ok() != Some(txid))
            {
                return Err(invalid("transaction ID does not match its bytes"));
            }
            if transaction.is_coinbase()
                || transaction
                    .input
                    .iter()
                    .any(|input| !input.witness.is_empty())
            {
                return Err(invalid(
                    "coinbase or witness transaction in transaction list",
                ));
            }
            if previous_txid.is_some_and(|previous| {
                previous
                    .as_byte_array()
                    .iter()
                    .rev()
                    .cmp(txid.as_byte_array().iter().rev())
                    != std::cmp::Ordering::Less
            }) {
                return Err(invalid("transactions are not in strict CTOR order"));
            }
            transaction_bytes = transaction_bytes
                .checked_add(bitcoin::consensus::serialize(&transaction).len())
                .ok_or_else(|| invalid("transaction size overflow"))?;
            previous_txid = Some(txid);
        }
        if transaction_bytes.saturating_add(81) > self.sizelimit as usize {
            return Err(invalid("transactions exceed node block size limit"));
        }
        Ok(())
    }

    /// Check the final size of an already validated BCH template with its coinbase.
    pub(crate) fn validate_bch_block_size(&self, coinbase: &Transaction) -> Result<(), WorkError> {
        let prefix_size = Header::SIZE
            + VarInt(self.transactions.len() as u64 + 1).size()
            + coinbase.total_size();
        let block_size = self
            .transactions
            .iter()
            .try_fold(prefix_size, |size, transaction| {
                size.checked_add(transaction.data.len() / 2)
            });
        if block_size.is_none_or(|size| size > self.sizelimit as usize) {
            return Err(WorkError {
                message: "BCH block including coinbase exceeds node block size limit".to_string(),
            });
        }
        Ok(())
    }

    /// The coinbase aux flags a share header records for this template.
    ///
    /// `parse_flags` pushes a single zero byte into the block coinbase both
    /// when the template has no `flags` entry (Bitcoin Core) and when the
    /// entry is an empty string (Bitcoin Cash Node). Validators rebuild that
    /// zero-byte push only from a header without flags, so an empty entry is
    /// recorded as no flags. Recording it as empty flags made every
    /// validator rebuild an empty push and reject the share.
    pub fn share_coinbaseaux_flags(&self) -> Option<CoinbaseAuxFlags> {
        self.coinbaseaux
            .get("flags")
            .filter(|flags| !flags.is_empty())
            .and_then(|flags| hex::decode(flags).ok())
            .map(|bytes| CoinbaseAuxFlags::new(&bytes))
    }
}

/// Extract flags from template coinbaseaux and convert to PushBytesBuf.
/// If flags are empty or absent, use a single byte with value 0.
pub(crate) fn parse_flags(flags: Option<String>) -> Result<PushBytesBuf, WorkError> {
    match flags {
        Some(flags) if flags.is_empty() => Ok(PushBytesBuf::from(&[0u8])),
        Some(flags) => {
            let decoded = hex::decode(&flags).map_err(|error| WorkError {
                message: format!("Invalid hex in coinbaseaux flags '{flags}': {error}"),
            })?;
            PushBytesBuf::try_from(decoded).map_err(|error| WorkError {
                message: format!("Coinbaseaux flags too large: {error}"),
            })
        }
        None => Ok(PushBytesBuf::from(&[0u8])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{bch_template_transaction, test_coinbase_transaction};
    use bitcoin::consensus::serialize;

    const BCHN_TEMPLATE: &str =
        include_str!("../../../../bitcoindrpc/test_data/bchn-regtest-template.json");

    #[test]
    fn bchn_template_without_bitcoin_fields_is_valid() {
        let template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        template.validate_bch().unwrap();
        assert_eq!(template.sizelimit, 32_000_000);
        assert_eq!(template.weightlimit, 0);
    }

    #[test]
    fn an_empty_bchn_flags_entry_is_recorded_as_no_share_flags() {
        let template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        assert_eq!(template.coinbaseaux.get("flags"), Some(&String::new()));
        assert_eq!(template.share_coinbaseaux_flags(), None);
    }

    #[test]
    fn a_missing_flags_entry_is_recorded_as_no_share_flags() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        template.coinbaseaux.clear();
        assert_eq!(template.share_coinbaseaux_flags(), None);
    }

    #[test]
    fn hex_flags_are_recorded_as_share_flags() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        template
            .coinbaseaux
            .insert("flags".to_string(), "0a0b".to_string());
        assert_eq!(
            template.share_coinbaseaux_flags(),
            Some(CoinbaseAuxFlags::new(&[0x0a, 0x0b]))
        );
    }

    #[test]
    fn bch_rejects_mismatched_target() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        template.target = "00".repeat(32);
        assert!(
            template
                .validate_bch()
                .unwrap_err()
                .message
                .contains("target")
        );
    }

    #[test]
    fn bch_rejects_coinbase_value_above_maximum_money() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        template.coinbasevalue = bitcoin::Amount::MAX_MONEY.to_sat() + 1;
        assert!(
            template
                .validate_bch()
                .unwrap_err()
                .message
                .contains("maximum money")
        );
    }

    #[test]
    fn bch_rejects_witness_commitment() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        template.default_witness_commitment = Some("6a24aa21a9ed".into());
        assert!(
            template
                .validate_bch()
                .unwrap_err()
                .message
                .contains("Bitcoin-only")
        );
    }

    #[test]
    fn bch_rejects_transaction_id_mismatch() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        let mut transaction = bch_template_transaction(1);
        transaction.txid = "00".repeat(32);
        template.transactions.push(transaction);
        assert!(
            template
                .validate_bch()
                .unwrap_err()
                .message
                .contains("transaction ID")
        );
    }

    #[test]
    fn bch_rejects_witness_transactions() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        let mut transaction = bch_template_transaction(1);
        let mut decoded = Transaction::try_from(&transaction).unwrap();
        decoded.input[0].witness.push([1u8]);
        transaction.data = bitcoin::consensus::encode::serialize_hex(&decoded);
        template.transactions.push(transaction);
        assert!(
            template
                .validate_bch()
                .unwrap_err()
                .message
                .contains("witness transaction")
        );
    }

    #[test]
    fn bch_rejects_duplicate_transaction_ids() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        let transaction = bch_template_transaction(1);
        template.transactions = vec![transaction.clone(), transaction];
        assert!(
            template
                .validate_bch()
                .unwrap_err()
                .message
                .contains("CTOR")
        );
    }

    #[test]
    fn bch_uses_display_order_for_ctor_and_rejects_reversed_order() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        template.transactions = vec![bch_template_transaction(1), bch_template_transaction(2)];
        template
            .transactions
            .sort_by(|left, right| left.txid.cmp(&right.txid));
        template.validate_bch().unwrap();
        template.transactions.reverse();
        assert!(
            template
                .validate_bch()
                .unwrap_err()
                .message
                .contains("CTOR")
        );
    }

    #[test]
    fn bch_rejects_transactions_over_node_size_limit() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        template.transactions.push(bch_template_transaction(1));
        template.sizelimit = 81;
        assert!(
            template
                .validate_bch()
                .unwrap_err()
                .message
                .contains("block size limit")
        );
    }

    #[test]
    fn bch_block_size_accepts_the_exact_limit_and_rejects_one_byte_less() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        template.transactions = vec![bch_template_transaction(1)];
        let coinbase = test_coinbase_transaction(1);
        let transactions = vec![
            coinbase.clone(),
            Transaction::try_from(&template.transactions[0]).unwrap(),
        ];
        template.sizelimit = (Header::SIZE + serialize(&transactions).len()) as u32;
        template.validate_bch().unwrap();
        template.validate_bch_block_size(&coinbase).unwrap();
        template.sizelimit -= 1;
        assert!(template.validate_bch_block_size(&coinbase).is_err());
    }

    #[test]
    fn bch_block_size_counts_the_compact_size_transaction_prefix() {
        let mut template: BlockTemplate = serde_json::from_str(BCHN_TEMPLATE).unwrap();
        let transaction = bch_template_transaction(1);
        let decoded = Transaction::try_from(&transaction).unwrap();
        template.transactions = vec![transaction; 252];
        let coinbase = test_coinbase_transaction(1);
        let mut transactions = vec![decoded; 253];
        transactions[0] = coinbase.clone();
        template.sizelimit = (Header::SIZE + serialize(&transactions).len()) as u32;
        template.validate_bch_block_size(&coinbase).unwrap();
        template.sizelimit -= 1;
        assert!(template.validate_bch_block_size(&coinbase).is_err());
    }

    #[test]
    fn malformed_template_hex_returns_an_error() {
        let mut transaction = bch_template_transaction(1);
        transaction.data = "invalid".into();
        assert!(Transaction::try_from(transaction).is_err());
    }

    #[test]
    fn malformed_template_transaction_returns_an_error() {
        let mut transaction = bch_template_transaction(1);
        transaction.data = "00".into();
        assert!(Transaction::try_from(transaction).is_err());
    }

    #[test]
    fn test_parse_flags() {
        let flags = parse_flags(Some(String::from(""))).unwrap();
        assert_eq!(flags.as_bytes(), &[0u8]);

        let flags = parse_flags(None).unwrap();
        assert_eq!(flags.as_bytes(), &[0u8]);

        let flags = parse_flags(Some(String::from("deadbeef"))).unwrap();
        assert_eq!(flags.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_flags_invalid_hex_returns_error() {
        let result = parse_flags(Some(String::from("not_valid_hex")));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .message
                .contains("Invalid hex in coinbaseaux flags")
        );
    }

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

        let bitcoin_tx = Transaction::try_from(tx_data).unwrap();
        assert_eq!(
            bitcoin_tx.compute_txid().to_string(),
            "74d7b9bf9f51dd7447e117b6a835a20b6f7d5d807285d1435da37574563ca525"
        );
    }

    #[test]
    fn test_load_transactions_from_json() {
        // Load the test JSON file
        let json_content = include_str!(
            "../../../../p2poolv2_tests/test_data/validation/stratum/gbt_with_transactions.json"
        );

        // Parse the JSON into BlockTemplate
        let block_template: BlockTemplate =
            serde_json::from_str(json_content).expect("Failed to parse JSON into BlockTemplate");

        // Verify we have transactions
        assert!(!block_template.transactions.is_empty());

        // Take the first transaction for detailed testing
        let first_tx = &block_template.transactions[0];

        // Convert to Bitcoin Transaction
        let btc_tx = Transaction::try_from(first_tx).unwrap();

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
