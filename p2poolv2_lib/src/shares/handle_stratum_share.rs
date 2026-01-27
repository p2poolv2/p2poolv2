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

#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::share_coinbase::build_share_coinbase;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::stratum::emission::Emission;
use bitcoin::merkle_tree;
use std::error::Error;
use tracing::debug;

/// Process a stratum share submission and store via ChainStoreHandle.
///
/// Builds a ShareBlock if there's a share commitment (p2p mode), or stores
/// just the PPLNS share for accounting (solo mode).
pub async fn handle_stratum_share(
    emission: Emission,
    chain_store_handle: &ChainStoreHandle,
    network: bitcoin::Network,
) -> Result<Option<ShareBlock>, Box<dyn Error + Send + Sync>> {
    // Send share to peers only in p2p mode, i.e. if the pool is run with a miner pubkey that results in a commitment
    if let Some(share_commitment) = emission.share_commitment {
        let coinbase = build_share_coinbase(share_commitment.miner_pubkey, network)
            .map_err(|e| format!("Failed to build coinbase. {e}"))?;

        // TODO: Get share chain transactions and use them here.
        let share_transactions = vec![coinbase];

        let txids = share_transactions
            .iter()
            .map(|tx| tx.compute_txid().to_raw_hash());
        let merkle_root = match merkle_tree::calculate_root(txids) {
            Some(merkle_root) => merkle_root,
            None => return Err("No coinbase found".into()),
        };

        let share_header = ShareHeader::from_commitment_and_header(
            share_commitment,
            emission.header,
            merkle_root.into(),
        );

        let mut bitcoin_transactions =
            Vec::with_capacity(emission.blocktemplate.transactions.len() + 1);
        bitcoin_transactions.push(emission.coinbase);
        bitcoin_transactions.extend(emission.blocktemplate.decode_transactions());

        // For now, send the entire template txdata, we will do tx
        // deltas or compact block optimisation later on
        let share_block = ShareBlock {
            header: share_header,
            transactions: share_transactions,
            bitcoin_transactions,
        };

        debug!(
            "Built share to add with {} txs",
            share_block.transactions.len()
        );

        // Store share block via ChainStoreHandle
        chain_store_handle
            .add_share(&share_block, true)
            .await
            .map_err(|e| format!("Failed to add share to chain: {e}"))?;

        Ok(Some(share_block))
    } else {
        // Store PPLNS share for accounting
        chain_store_handle
            .add_pplns_share(emission.pplns)
            .await
            .map_err(|e| format!("Failed to add PPLNS share: {e}"))?;

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use crate::store::writer::StoreError;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::test_utils::create_test_commitment;
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget};
    use bitcoin::{Transaction, absolute::LockTime, transaction::Version};
    use std::collections::HashMap;
    use std::sync::Arc;

    /// Helper to create a minimal BlockTemplate for testing
    fn create_test_blocktemplate() -> BlockTemplate {
        BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: HashMap::new(),
            vbrequired: 0,
            previousblockhash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            transactions: vec![],
            coinbaseaux: HashMap::new(),
            coinbasevalue: 5000000000,
            longpollid: "".to_string(),
            target: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "207fffff".to_string(),
            height: 1,
            default_witness_commitment: None,
        }
    }

    /// Helper to create a test Emission with no share commitment (solo mining mode)
    fn create_test_emission_without_commitment() -> Emission {
        let pplns = SimplePplnsShare {
            user_id: 1,
            difficulty: 1000,
            btcaddress: Some("tb1qtest".to_string()),
            workername: Some("worker1".to_string()),
            n_time: 1700000000,
            job_id: "test_job_1".to_string(),
            extranonce2: "00000001".to_string(),
            nonce: "12345".to_string(),
        };

        let bitcoin_header = Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1700000000,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 12345,
        };

        // Create a minimal coinbase transaction
        let coinbase = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        Emission {
            pplns,
            header: bitcoin_header,
            coinbase,
            blocktemplate: Arc::new(create_test_blocktemplate()),
            share_commitment: None,
        }
    }

    /// Helper to create a test Emission with share commitment (p2p mining mode)
    fn create_test_emission_with_commitment() -> Emission {
        let pplns = SimplePplnsShare {
            user_id: 1,
            difficulty: 1000,
            btcaddress: Some("tb1qtest".to_string()),
            workername: Some("worker1".to_string()),
            n_time: 1700000000,
            job_id: "test_job_1".to_string(),
            extranonce2: "00000001".to_string(),
            nonce: "12345".to_string(),
        };

        let bitcoin_header = Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1700000000,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 12345,
        };

        // Create a minimal coinbase transaction
        let coinbase = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let commitment = create_test_commitment();

        Emission {
            pplns,
            header: bitcoin_header,
            coinbase,
            blocktemplate: Arc::new(create_test_blocktemplate()),
            share_commitment: Some(commitment),
        }
    }

    #[tokio::test]
    async fn test_handle_stratum_share_without_commitment_returns_none() {
        let mut mock_chain_store = ChainStoreHandle::default();

        // Mock add_pplns_share to succeed
        mock_chain_store
            .expect_add_pplns_share()
            .returning(|_| Ok(()));

        let emission = create_test_emission_without_commitment();

        let result =
            handle_stratum_share(emission, &mock_chain_store, bitcoin::Network::Signet).await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_handle_stratum_share_with_commitment_returns_share_block() {
        let mut mock_chain_store = ChainStoreHandle::default();

        // Mock add_share to succeed
        mock_chain_store.expect_add_share().returning(|_, _| Ok(()));

        let emission = create_test_emission_with_commitment();

        let result =
            handle_stratum_share(emission, &mock_chain_store, bitcoin::Network::Signet).await;

        assert!(result.is_ok());
        let share_block = result.unwrap();
        assert!(share_block.is_some());

        let share_block = share_block.unwrap();
        // Verify the share block has the expected structure
        assert_eq!(share_block.transactions.len(), 1); // One share coinbase
        // bitcoin_transactions includes the emission coinbase (1) + decoded template txs (0)
        assert_eq!(share_block.bitcoin_transactions.len(), 1);
    }

    #[tokio::test]
    async fn test_handle_stratum_share_channel_closed_returns_error() {
        let mut mock_chain_store = ChainStoreHandle::default();

        // Mock add_pplns_share to return an error (simulating channel closed)
        mock_chain_store
            .expect_add_pplns_share()
            .returning(|_| Err(StoreError::ChannelClosed));

        let emission = create_test_emission_without_commitment();

        let result =
            handle_stratum_share(emission, &mock_chain_store, bitcoin::Network::Signet).await;

        assert!(result.is_err());
        // The error message will contain information about the channel being closed
        assert!(result.unwrap_err().to_string().contains("PPLNS"));
    }

    #[tokio::test]
    async fn test_handle_stratum_share_builds_correct_share_header() {
        let mut mock_chain_store = ChainStoreHandle::default();

        // Mock add_share to succeed
        mock_chain_store.expect_add_share().returning(|_, _| Ok(()));

        let emission = create_test_emission_with_commitment();
        let expected_commitment = emission.share_commitment.clone().unwrap();
        let expected_bitcoin_header = emission.header;

        let result =
            handle_stratum_share(emission, &mock_chain_store, bitcoin::Network::Signet).await;

        assert!(result.is_ok());
        let share_block = result.unwrap().unwrap();

        // Verify share header fields from commitment
        assert_eq!(
            share_block.header.prev_share_blockhash,
            expected_commitment.prev_share_blockhash
        );
        assert_eq!(share_block.header.uncles, expected_commitment.uncles);
        assert_eq!(
            share_block.header.miner_pubkey,
            expected_commitment.miner_pubkey
        );
        assert_eq!(share_block.header.bits, expected_commitment.bits);
        assert_eq!(share_block.header.time, expected_commitment.time);

        // Verify bitcoin header is preserved
        assert_eq!(share_block.header.bitcoin_header, expected_bitcoin_header);
    }

    #[tokio::test]
    async fn test_handle_stratum_share_with_bitcoin_transactions() {
        use crate::stratum::work::block_template::TemplateTransaction;
        use bitcoin::consensus::Encodable;

        let mut mock_chain_store = ChainStoreHandle::default();

        // Mock add_share to succeed
        mock_chain_store.expect_add_share().returning(|_, _| Ok(()));

        // Create emission with some bitcoin transactions
        let pplns = SimplePplnsShare {
            user_id: 1,
            difficulty: 1000,
            btcaddress: Some("tb1qtest".to_string()),
            workername: Some("worker1".to_string()),
            n_time: 1700000000,
            job_id: "test_job_1".to_string(),
            extranonce2: "00000001".to_string(),
            nonce: "12345".to_string(),
        };

        let bitcoin_header = Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1700000000,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 12345,
        };

        // Create a coinbase transaction
        let coinbase = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // Create a valid template transaction by serializing a real Transaction
        let template_source_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let mut tx_bytes = Vec::new();
        template_source_tx.consensus_encode(&mut tx_bytes).unwrap();
        let tx_hex = hex::encode(&tx_bytes);

        let template_tx = TemplateTransaction {
            data: tx_hex.clone(),
            txid: template_source_tx.compute_txid().to_string(),
            hash: template_source_tx.compute_wtxid().to_string(),
            depends: vec![],
            fee: 0,
            sigops: 0,
            weight: 100,
        };

        let mut blocktemplate = create_test_blocktemplate();
        blocktemplate.transactions = vec![template_tx.clone(), template_tx];

        let commitment = create_test_commitment();

        let emission = Emission {
            pplns,
            header: bitcoin_header,
            coinbase,
            blocktemplate: Arc::new(blocktemplate),
            share_commitment: Some(commitment),
        };

        let result =
            handle_stratum_share(emission, &mock_chain_store, bitcoin::Network::Signet).await;

        assert!(result.is_ok());
        let share_block = result.unwrap().unwrap();

        // Verify bitcoin transactions are included (1 coinbase + 2 from template)
        assert_eq!(share_block.bitcoin_transactions.len(), 3);
    }

    #[tokio::test]
    async fn test_handle_stratum_share_pplns_data_stored_correctly() {
        let mut mock_chain_store = ChainStoreHandle::default();

        // Mock add_pplns_share to succeed
        mock_chain_store
            .expect_add_pplns_share()
            .returning(|_| Ok(()));

        let emission = create_test_emission_without_commitment();

        let result =
            handle_stratum_share(emission, &mock_chain_store, bitcoin::Network::Signet).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none()); // No share block for standlone pool mode
    }
}
