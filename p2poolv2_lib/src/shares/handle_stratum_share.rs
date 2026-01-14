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
use crate::shares::chain::chain_store::ChainStore;
#[cfg(not(test))]
use crate::shares::chain::chain_store::ChainStore;
use crate::shares::share_block::share_coinbase::build_share_coinbase;
use crate::shares::share_block::{ShareBlock, ShareHeader};
use crate::stratum::emission::Emission;
use bitcoin::merkle_tree;
use std::error::Error;
use std::sync::Arc;
use tracing::debug;

/// Save share to database for persistence in case we need to recover from a crash
/// Shares are saved with a TTL for 1 week or when we reach accumulated work required for 5 blocks at current difficulty.
pub fn handle_stratum_share(
    emission: Emission,
    chain_store: Arc<ChainStore>,
    network: bitcoin::Network,
) -> Result<Option<ShareBlock>, Box<dyn Error + Send + Sync>> {
    // save pplns share for accounting
    chain_store.add_pplns_share(emission.pplns)?;

    // Send share to peers only in p2p mode, i.e. if the pool is run with a miner pubkey that results in a commitment
    if let Some(share_commitment) = emission.share_commitment {
        let Ok(coinbase) = build_share_coinbase(share_commitment.miner_pubkey, network) else {
            return Err("Failed to build coinbase. Will quit".into());
        };
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
            emission.block.header,
            merkle_root.into(),
        );
        // For now, send the entire block, we will do tx deltas or compact block optimisation later on
        let share_block = ShareBlock {
            header: share_header,
            transactions: share_transactions,
            bitcoin_transactions: emission.block.txdata,
        };

        debug!(
            "Built share to add with {} txs",
            share_block.transactions.len()
        );

        // save and reorg share
        chain_store.add_share(&share_block, true)?;

        Ok(Some(share_block))
    } else {
        debug!("No share commitment emitted by stratum. Won't send share to peers");
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use crate::shares::chain::chain_store::MockChainStore;
    use crate::test_utils::create_test_commitment;
    use bitcoin::block::Header;
    use bitcoin::hashes::Hash;
    use bitcoin::{Block, BlockHash, CompactTarget};
    use bitcoin::{Transaction, absolute::LockTime, transaction::Version};

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

        let block = Block {
            header: bitcoin_header,
            txdata: vec![],
        };

        Emission {
            pplns,
            block,
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

        let block = Block {
            header: bitcoin_header,
            txdata: vec![],
        };

        let commitment = create_test_commitment();

        Emission {
            pplns,
            block,
            share_commitment: Some(commitment),
        }
    }

    #[test]
    fn test_handle_stratum_share_without_commitment_returns_none() {
        let mut mock_store = MockChainStore::default();

        // Expect add_pplns_share to be called once and succeed
        mock_store
            .expect_add_pplns_share()
            .times(1)
            .returning(|_| Ok(()));

        let emission = create_test_emission_without_commitment();
        let store = Arc::new(mock_store);

        let result = handle_stratum_share(emission, store, bitcoin::Network::Signet);

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_handle_stratum_share_with_commitment_returns_share_block() {
        let mut mock_store = MockChainStore::default();

        // Expect add_pplns_share to be called once and succeed
        mock_store
            .expect_add_pplns_share()
            .times(1)
            .returning(|_| Ok(()));

        // Expect add_share to be called once and succeed
        mock_store
            .expect_add_share()
            .times(1)
            .returning(|_, _| Ok(()));

        let emission = create_test_emission_with_commitment();
        let store = Arc::new(mock_store);

        let result = handle_stratum_share(emission, store, bitcoin::Network::Signet);

        assert!(result.is_ok());
        let share_block = result.unwrap();
        assert!(share_block.is_some());

        let share_block = share_block.unwrap();
        // Verify the share block has the expected structure
        assert_eq!(share_block.transactions.len(), 1); // One dummy coinbase
        assert!(share_block.bitcoin_transactions.is_empty()); // No bitcoin transactions in test
    }

    #[test]
    fn test_handle_stratum_share_propagates_add_pplns_error() {
        let mut mock_store = MockChainStore::default();

        // Expect add_pplns_share to be called once and return an error
        mock_store
            .expect_add_pplns_share()
            .times(1)
            .returning(|_| Err("PPLNS storage error".into()));

        let emission = create_test_emission_without_commitment();
        let store = Arc::new(mock_store);

        let result = handle_stratum_share(emission, store, bitcoin::Network::Signet);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("PPLNS storage error")
        );
    }

    #[test]
    fn test_handle_stratum_share_propagates_add_share_error() {
        let mut mock_store = MockChainStore::default();

        // Expect add_pplns_share to be called once and succeed
        mock_store
            .expect_add_pplns_share()
            .times(1)
            .returning(|_| Ok(()));

        // Expect add_share to be called once and return an error
        mock_store
            .expect_add_share()
            .times(1)
            .returning(|_, _| Err("Chain store error".into()));

        let emission = create_test_emission_with_commitment();
        let store = Arc::new(mock_store);

        let result = handle_stratum_share(emission, store, bitcoin::Network::Signet);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Chain store error")
        );
    }

    #[test]
    fn test_handle_stratum_share_builds_correct_share_header() {
        let mut mock_store = MockChainStore::default();

        mock_store
            .expect_add_pplns_share()
            .times(1)
            .returning(|_| Ok(()));

        mock_store
            .expect_add_share()
            .times(1)
            .returning(|_, _| Ok(()));

        let emission = create_test_emission_with_commitment();
        let expected_commitment = emission.share_commitment.clone().unwrap();
        let expected_bitcoin_header = emission.block.header;

        let store = Arc::new(mock_store);
        let result = handle_stratum_share(emission, store, bitcoin::Network::Signet);

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

    #[test]
    fn test_handle_stratum_share_with_bitcoin_transactions() {
        let mut mock_store = MockChainStore::default();

        mock_store
            .expect_add_pplns_share()
            .times(1)
            .returning(|_| Ok(()));

        mock_store
            .expect_add_share()
            .times(1)
            .returning(|_, _| Ok(()));

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

        // Create a simple transaction
        let test_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let block = Block {
            header: bitcoin_header,
            txdata: vec![test_tx.clone(), test_tx.clone()],
        };

        let commitment = create_test_commitment();

        let emission = Emission {
            pplns,
            block,
            share_commitment: Some(commitment),
        };

        let store = Arc::new(mock_store);
        let result = handle_stratum_share(emission, store, bitcoin::Network::Signet);

        assert!(result.is_ok());
        let share_block = result.unwrap().unwrap();

        // Verify bitcoin transactions are included
        assert_eq!(share_block.bitcoin_transactions.len(), 2);
    }

    #[test]
    fn test_handle_stratum_share_pplns_data_passed_correctly() {
        let mut mock_store = MockChainStore::default();

        // Capture the PPLNS share that's passed to verify it's correct
        mock_store
            .expect_add_pplns_share()
            .times(1)
            .withf(|pplns: &SimplePplnsShare| {
                pplns.user_id == 1
                    && pplns.difficulty == 1000
                    && pplns.job_id == "test_job_1"
                    && pplns.n_time == 1700000000
            })
            .returning(|_| Ok(()));

        let emission = create_test_emission_without_commitment();
        let store = Arc::new(mock_store);

        let result = handle_stratum_share(emission, store, bitcoin::Network::Signet);
        assert!(result.is_ok());
    }
}
