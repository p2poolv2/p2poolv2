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

use crate::node::p2p_message_handlers::MAX_HEADERS_IN_RESPONSE;
use crate::node::request_response_handler::block_fetcher::{BlockFetcherEvent, BlockFetcherHandle};
use crate::node::{SwarmSend, messages::Message};
#[cfg(test)]
#[mockall_double::double]
use crate::pool_difficulty::PoolDifficulty;
#[cfg(not(test))]
use crate::pool_difficulty::PoolDifficulty;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_block::{
    MAX_POOL_TARGET, MIN_CUMULATIVE_CHAIN_WORK_MULTIPLIER, ShareHeader,
};
use crate::shares::validation::ShareValidator;
use crate::store::block_tx_metadata::BlockMetadata;
use crate::store::writer::StoreError;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Target, Work};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Handle ShareHeaders received from a peer.
///
/// The peer_id identifies the peer that sent the headers, allowing
/// follow-up requests to be directed back to the same peer.
///
/// Phase 1 -- Validate:
///   - Each header meets minimum pool difficulty (uncle count + target floor)
///   - Headers form a single chain with uncles correctly interleaved
///   - Each header's bits matches the ASERT-computed target from its parent
///   - Cumulative chain work exceeds minimum threshold
///
/// Phase 2 -- Organise:
///   - Store validated headers via organise_header (persists metadata for later
///     validate_with_pool_difficulty in validate_share_block)
///
/// Then either request more headers or trigger block fetch.
pub async fn handle_share_headers<C: Send + Sync>(
    peer_id: libp2p::PeerId,
    share_headers: Vec<ShareHeader>,
    chain_store_handle: ChainStoreHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
    block_fetcher_handle: BlockFetcherHandle,
    share_validator: &(dyn ShareValidator + Send + Sync),
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received {} ShareHeaders", share_headers.len());

    // No new headers, start fetching any block data for received headers
    if share_headers.is_empty() {
        return trigger_or_request(
            peer_id,
            &share_headers,
            &chain_store_handle,
            &swarm_tx,
            &block_fetcher_handle,
            None,
        )
        .await;
    }

    // Phase 1: Validate the header chain in memory
    validate_header_chain(&share_headers, &chain_store_handle, share_validator)?;

    // Phase 2: Organise validated headers into the candidate chain
    for header in &share_headers {
        chain_store_handle.organise_header(header.clone()).await?;
    }

    // The batch is sorted by increasing height, so the first header
    // is the lowest. Use its height as min_scan_height so
    // trigger_block_fetch can find fork blocks at or below the
    // confirmed tip.
    let first_blockhash = share_headers[0].block_hash();
    let min_organised_height = chain_store_handle
        .get_block_metadata(&first_blockhash)
        .ok()
        .and_then(|metadata| metadata.expected_height);

    trigger_or_request(
        peer_id,
        &share_headers,
        &chain_store_handle,
        &swarm_tx,
        &block_fetcher_handle,
        min_organised_height,
    )
    .await
}

/// Validate the received header batch as a connected DAG.
///
/// The batch contains a mix of main chain and uncle headers. Validation
/// checks that the batch forms a connected DAG (every header's parent is
/// either earlier in the batch or in the store), that every header meets
/// ASERT difficulty, that all declared uncle hashes are available, and
/// that cumulative work exceeds the minimum threshold.
fn validate_header_chain(
    share_headers: &[ShareHeader],
    chain_store_handle: &ChainStoreHandle,
    share_validator: &(dyn ShareValidator + Send + Sync),
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let pool_difficulty = share_validator.pool_difficulty();

    let (anchor_hash, anchor_metadata) = find_chain_anchor(share_headers, chain_store_handle)?;
    debug!(
        "Anchor hash {:?} and anchor height {:?}",
        anchor_hash, anchor_metadata.expected_height
    );

    let (batch_hashes, cumulative_chain_work) = validate_dag_connectivity_and_difficulty(
        share_headers,
        share_validator,
        pool_difficulty,
        anchor_hash,
        chain_store_handle,
    )?;
    verify_all_uncles_available(share_headers, &batch_hashes, chain_store_handle)?;
    validate_cumulative_work(anchor_metadata.chain_work, cumulative_chain_work)?;

    debug!(
        "Validated {} headers, cumulative chain work: {cumulative_chain_work}",
        share_headers.len(),
    );
    Ok(())
}

/// Get the blockhash's timestamp and height, checking the batch-local
/// cache first and falling back to the store. Store results are cached
/// for subsequent lookups within the same batch.
fn get_share_time_and_height(
    blockhash: &BlockHash,
    cache: &mut HashMap<BlockHash, (u32, u32)>,
    chain_store_handle: &ChainStoreHandle,
) -> Result<(u32, u32), Box<dyn Error + Send + Sync>> {
    if let Some(&cached) = cache.get(blockhash) {
        return Ok(cached);
    }
    let metadata = chain_store_handle.get_block_metadata(blockhash)?;
    let header = chain_store_handle.get_share_header(blockhash)?;
    let height = metadata
        .expected_height
        .ok_or_else(|| StoreError::Database(format!("No height found for {blockhash}")))?;
    let result = (header.time, height);
    cache.insert(*blockhash, result);
    Ok(result)
}

/// Validate that the batch forms a connected DAG with valid difficulty.
///
/// Every header's parent must be either already processed in this batch
/// or present in the store. Every header must pass minimum difficulty
/// and ASERT target validation.
///
/// Returns the set of all blockhashes in the batch and the cumulative
/// work across all headers.
fn validate_dag_connectivity_and_difficulty(
    share_headers: &[ShareHeader],
    share_validator: &(dyn ShareValidator + Send + Sync),
    pool_difficulty: &PoolDifficulty,
    anchor_hash: BlockHash,
    chain_store_handle: &ChainStoreHandle,
) -> Result<(HashSet<BlockHash>, Work), Box<dyn Error + Send + Sync>> {
    let mut known_hashes: HashSet<BlockHash> = HashSet::with_capacity(share_headers.len() + 1);
    known_hashes.insert(anchor_hash);

    let mut cumulative_work = Work::from_hex("0x00").unwrap();
    let mut time_height_cache: HashMap<BlockHash, (u32, u32)> =
        HashMap::with_capacity(share_headers.len() + 1);

    for header in share_headers {
        share_validator.validate_header_minimum_difficulty(header)?;

        let parent_hash = header.prev_share_blockhash;
        if !known_hashes.contains(&parent_hash)
            && chain_store_handle.get_block_metadata(&parent_hash).is_err()
        {
            return Err(format!(
                "Header {} has parent {} which is not in batch or store",
                header.block_hash(),
                parent_hash
            )
            .into());
        }

        let (parent_time, parent_height) =
            get_share_time_and_height(&parent_hash, &mut time_height_cache, chain_store_handle)?;

        let expected_bits = pool_difficulty.calculate_target_clamped(parent_time, parent_height);
        if header.bits != expected_bits {
            let block_hash = header.block_hash();
            return Err(format!(
                "ASERT mismatch for {block_hash}: declared bits {:#010x}, expected {:#010x}",
                header.bits.to_consensus(),
                expected_bits.to_consensus()
            )
            .into());
        }

        let header_hash = header.block_hash();
        time_height_cache.insert(header_hash, (header.time, parent_height + 1));
        known_hashes.insert(header_hash);
        cumulative_work = cumulative_work + header.get_work();
    }

    Ok((known_hashes, cumulative_work))
}

/// Verify every uncle hash declared by any header in the batch exists
/// either as another header in this batch or in the store. Catches
/// phantom uncle references that no peer ever sent.
fn verify_all_uncles_available(
    share_headers: &[ShareHeader],
    batch_hashes: &HashSet<BlockHash>,
    chain_store_handle: &ChainStoreHandle,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for header in share_headers {
        for uncle_hash in &header.uncles {
            if !batch_hashes.contains(uncle_hash)
                && chain_store_handle.get_block_metadata(uncle_hash).is_err()
            {
                return Err(format!(
                    "Declared uncle {uncle_hash} not delivered in batch and not in store"
                )
                .into());
            }
        }
    }
    Ok(())
}

/// Find the chain anchor: the highest-height parent from the batch that
/// exists in our store.
///
/// Collects all `prev_share_blockhash` values that are NOT themselves
/// hashes of headers in this batch (i.e., external parents from the
/// store). Among those, picks the one with the highest expected_height
/// to avoid deep-fork uncle parents pulling the anchor too far back.
///
/// Uncle references will all be the hash which is also the anchor
/// point, or lower, they can't be higher than the anchor point.
fn find_chain_anchor(
    share_headers: &[ShareHeader],
    chain_store_handle: &ChainStoreHandle,
) -> Result<(BlockHash, BlockMetadata), Box<dyn Error + Send + Sync>> {
    let batch_hashes: HashSet<BlockHash> = share_headers
        .iter()
        .map(|header| header.block_hash())
        .collect();

    let external_parents: Vec<BlockHash> = share_headers
        .iter()
        .map(|header| header.prev_share_blockhash)
        .filter(|parent| !batch_hashes.contains(parent))
        .collect();

    let metadata_results = chain_store_handle.get_block_metadata_batch(&external_parents);

    let best_anchor = metadata_results
        .into_iter()
        .max_by_key(|(_, metadata)| metadata.expected_height);

    best_anchor.ok_or_else(|| "No header in batch has a parent in the store".into())
}

/// Verify cumulative chain work exceeds the minimum threshold.
fn validate_cumulative_work(
    anchor_chain_work: Work,
    batch_chain_work: Work,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let single_share_work =
        Target::from_compact(CompactTarget::from_consensus(MAX_POOL_TARGET)).to_work();
    let zero_work = Work::from_hex("0x00").unwrap();
    let min_cumulative_work = (0..MIN_CUMULATIVE_CHAIN_WORK_MULTIPLIER)
        .fold(zero_work, |accumulated, _| accumulated + single_share_work);
    let candidate_work = anchor_chain_work + batch_chain_work;

    if candidate_work < min_cumulative_work {
        return Err(format!(
            "Cumulative chain work {candidate_work} below minimum {min_cumulative_work}"
        )
        .into());
    }
    Ok(())
}

/// Either trigger block fetch or request next batch of headers.
async fn trigger_or_request<C: Send + Sync>(
    peer_id: libp2p::PeerId,
    share_headers: &[ShareHeader],
    chain_store_handle: &ChainStoreHandle,
    swarm_tx: &mpsc::Sender<SwarmSend<C>>,
    block_fetcher_handle: &BlockFetcherHandle,
    min_organised_height: Option<u32>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if share_headers.len() < MAX_HEADERS_IN_RESPONSE {
        trigger_block_fetch(
            peer_id,
            chain_store_handle,
            block_fetcher_handle,
            min_organised_height,
        )
        .await
    } else {
        request_next_headers(peer_id, share_headers, swarm_tx).await
    }
}

/// Header sync is complete -- query for candidate blocks missing full
/// block data and send them to the block fetcher for download.
///
/// When `min_organised_height` is provided, the scan extends down to
/// that height so fork blocks at or below the confirmed tip are
/// included in the fetch request.
async fn trigger_block_fetch(
    peer_id: libp2p::PeerId,
    chain_store_handle: &ChainStoreHandle,
    block_fetcher_handle: &BlockFetcherHandle,
    min_organised_height: Option<u32>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Header sync complete, triggering block fetch for missing data");
    let missing_blockhashes =
        chain_store_handle.get_candidate_blocks_missing_data(min_organised_height)?;
    if !missing_blockhashes.is_empty() {
        info!(
            "Requesting {} blocks from block fetcher",
            missing_blockhashes.len()
        );
        let use_peer = chain_store_handle.is_current();
        if let Err(send_error) = block_fetcher_handle
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: missing_blockhashes,
                peer_id,
                use_peer,
            })
            .await
        {
            error!(
                "Failed to send FetchBlocks to block fetcher: {}",
                send_error
            );
        }
    } else {
        debug!("No candidate blocks missing data");
    }
    Ok(())
}

/// More headers are available -- send a follow-up GetShareHeaders
/// request to the same peer starting from the last received header.
async fn request_next_headers<C: Send + Sync>(
    peer_id: libp2p::PeerId,
    share_headers: &[ShareHeader],
    swarm_tx: &mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Requesting more share headers");
    let stop_block_hash = BlockHash::all_zeros();
    let last_block_hash = share_headers.last().unwrap().block_hash();
    let getheaders_request = Message::GetShareHeaders(vec![last_block_hash], stop_block_hash);
    debug!("Sending getheaders {getheaders_request}");
    if let Err(send_error) = swarm_tx
        .send(SwarmSend::Request(peer_id, getheaders_request))
        .await
    {
        error!("Failed to send getheaders request: {}", send_error);
        return Err(format!("Failed to send getheaders request: {send_error}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::SwarmSend;
    use crate::node::messages::Message;
    use crate::node::request_response_handler::block_fetcher;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::shares::validation::MockDefaultShareValidator;
    use crate::store::block_tx_metadata::{BlockMetadata, Status};
    use crate::test_utils::TestShareBlockBuilder;
    use tokio::sync::{mpsc, oneshot};

    /// Build a single test header with bits set to MAX_POOL_TARGET so it
    /// passes both minimum difficulty and ASERT validation (since ASERT
    /// computes MAX_POOL_TARGET from the genesis anchor).
    fn build_valid_test_header() -> ShareHeader {
        let mut header = TestShareBlockBuilder::new().build().header;
        header.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        header
    }

    /// Set up chain_store_handle mocks for validate_header_chain:
    /// genesis header, parent header lookup, and parent metadata.
    fn setup_chain_validation_mocks(chain_store_handle: &mut ChainStoreHandle) {
        let template_header = build_valid_test_header();
        let genesis_header = template_header.clone();
        chain_store_handle
            .expect_get_genesis_header()
            .returning(move || Ok(genesis_header.clone()));
        let parent_header = template_header.clone();
        chain_store_handle
            .expect_get_share_header()
            .returning(move |_| Ok(parent_header.clone()));
        chain_store_handle
            .expect_get_block_metadata()
            .returning(|_| {
                Ok(BlockMetadata {
                    expected_height: Some(0),
                    chain_work: Work::from_hex("0x00").unwrap(),
                    status: Status::Confirmed,
                })
            });
        chain_store_handle
            .expect_get_block_metadata_batch()
            .returning(|hashes| {
                hashes
                    .iter()
                    .map(|hash| {
                        (
                            *hash,
                            BlockMetadata {
                                expected_height: Some(0),
                                chain_work: Work::from_hex("0x00").unwrap(),
                                status: Status::Confirmed,
                            },
                        )
                    })
                    .collect()
            });
    }

    fn setup_minimum_difficulty_mock(mock_validator: &mut MockDefaultShareValidator) {
        mock_validator
            .expect_validate_header_minimum_difficulty()
            .returning(|_| Ok(()));
        let mut pool_difficulty = PoolDifficulty::default();
        pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _| CompactTarget::from_consensus(MAX_POOL_TARGET));
        mock_validator
            .expect_pool_difficulty()
            .return_const(pool_difficulty);
    }

    #[tokio::test]
    async fn test_fewer_than_max_headers_does_not_send_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_organise_header()
            .returning(|_| Ok(None));
        chain_store_handle
            .expect_get_candidate_blocks_missing_data()
            .returning(|_| Ok(Vec::new()));
        setup_chain_validation_mocks(&mut chain_store_handle);

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();

        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let share_headers = vec![build_valid_test_header()];

        let result = handle_share_headers(
            peer_id,
            share_headers,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            &mock_validator,
        )
        .await;
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());

        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_empty_headers_does_not_send_getheaders() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_get_candidate_blocks_missing_data()
            .returning(|_| Ok(Vec::new()));
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();

        let mock_validator = MockDefaultShareValidator::default();
        let share_headers: Vec<ShareHeader> = Vec::new();

        let result = handle_share_headers(
            peer_id,
            share_headers,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            &mock_validator,
        )
        .await;

        assert!(result.is_ok());
        assert!(swarm_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_share_headers_sends_getheaders_to_same_peer() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_organise_header()
            .returning(|_| Ok(None));
        setup_chain_validation_mocks(&mut chain_store_handle);

        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();

        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let first = build_valid_test_header();
        let mut parent_hash = first.prev_share_blockhash;
        let mut share_headers = Vec::with_capacity(MAX_HEADERS_IN_RESPONSE);
        for nonce in 0..MAX_HEADERS_IN_RESPONSE as u32 {
            let mut header = TestShareBlockBuilder::new()
                .prev_share_blockhash(parent_hash.to_string())
                .nonce(nonce)
                .build()
                .header;
            header.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
            parent_hash = header.block_hash();
            share_headers.push(header);
        }
        let expected_last_hash = share_headers.last().unwrap().block_hash();

        let result = handle_share_headers(
            peer_id,
            share_headers,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            &mock_validator,
        )
        .await;

        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());

        let swarm_message = swarm_rx
            .try_recv()
            .expect("expected a follow-up getheaders request");
        match swarm_message {
            SwarmSend::Request(sent_peer_id, Message::GetShareHeaders(locator, stop_hash)) => {
                assert_eq!(sent_peer_id, peer_id);
                assert_eq!(locator, vec![expected_last_hash]);
                assert_eq!(stop_hash, BlockHash::all_zeros());
            }
            other => panic!("expected SwarmSend::Request with GetShareHeaders, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_fewer_than_max_headers_sends_fetch_blocks_event() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_organise_header()
            .returning(|_| Ok(None));

        let missing_hash = bitcoin::BlockHash::all_zeros();
        let expected_hashes = vec![missing_hash];
        let returned_hashes = expected_hashes.clone();
        chain_store_handle
            .expect_get_candidate_blocks_missing_data()
            .returning(move |_| Ok(returned_hashes.clone()));
        chain_store_handle.expect_is_current().returning(|| true);
        setup_chain_validation_mocks(&mut chain_store_handle);

        let (swarm_tx, _swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);
        let (block_fetcher_handle, mut block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();

        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let share_headers = vec![build_valid_test_header()];

        let result = handle_share_headers(
            peer_id,
            share_headers,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            &mock_validator,
        )
        .await;

        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());

        let event = block_fetcher_rx
            .try_recv()
            .expect("expected a FetchBlocks event");
        match event {
            BlockFetcherEvent::FetchBlocks {
                blockhashes,
                peer_id: event_peer_id,
                use_peer,
            } => {
                assert_eq!(blockhashes, expected_hashes);
                assert_eq!(event_peer_id, peer_id);
                assert!(use_peer, "use_peer should be true when chain is current");
            }
            other => panic!("expected FetchBlocks event, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_asert_mismatch_rejected() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);

        let (swarm_tx, _swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();

        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        // Header with wrong bits (genesis bits instead of MAX_POOL_TARGET)
        let header = TestShareBlockBuilder::new().build().header;
        // header.bits is 0x1b4188f5 (genesis), but ASERT expects MAX_POOL_TARGET
        let share_headers = vec![header];

        let result = handle_share_headers(
            peer_id,
            share_headers,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            &mock_validator,
        )
        .await;

        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("ASERT mismatch"),
            "Expected ASERT mismatch error"
        );
    }

    #[test]
    fn test_validate_header_chain_accepts_single_header_linked_to_anchor() {
        let anchor = TestShareBlockBuilder::new().nonce(1).build();
        let mut child = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        child.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let result = validate_header_chain(&[child], &chain_store_handle, &mock_validator);
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());
    }

    #[test]
    fn test_validate_header_chain_accepts_linear_chain() {
        let anchor = TestShareBlockBuilder::new().nonce(1).build();
        let mut share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        share_a.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .nonce(3)
            .build()
            .header;
        share_b.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let headers = vec![share_a, share_b];
        let result = validate_header_chain(&headers, &chain_store_handle, &mock_validator);
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());
    }

    #[test]
    fn test_validate_header_chain_accepts_uncle_before_nephew() {
        let anchor = TestShareBlockBuilder::new().nonce(1).build();
        let mut share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        share_a.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        // uncle is a sibling of share_a (same parent = anchor)
        let mut uncle = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(3)
            .build()
            .header;
        uncle.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        // share_b follows share_a on the confirmed chain
        let mut share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .uncles(vec![uncle.block_hash()])
            .nonce(4)
            .build()
            .header;
        share_b.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        // Order: share_a, uncle, share_b (as get_descendant_blockhashes produces)
        let headers = vec![share_a, uncle, share_b];
        let result = validate_header_chain(&headers, &chain_store_handle, &mock_validator);
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());
    }

    #[test]
    fn test_validate_header_chain_rejects_first_header_not_linked_to_anchor() {
        let unrelated = TestShareBlockBuilder::new().nonce(99).build();
        let mut child = TestShareBlockBuilder::new()
            .prev_share_blockhash(unrelated.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        child.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        // No header in the batch has a parent that the store recognises.
        let mut chain_store_handle = ChainStoreHandle::default();
        chain_store_handle
            .expect_get_block_metadata()
            .returning(|_| Err(StoreError::NotFound("not found".into())));
        chain_store_handle
            .expect_get_block_metadata_batch()
            .returning(|_| Vec::new());
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let result = validate_header_chain(&[child], &chain_store_handle, &mock_validator);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No header in batch has a parent in the store"),
        );
    }

    #[test]
    fn test_validate_header_chain_rejects_forest_with_disconnected_subtree() {
        let anchor = TestShareBlockBuilder::new().nonce(1).build();
        let anchor_hash = anchor.block_hash();
        let mut share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        share_a.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        // share_c has an unrelated parent, forming a disconnected subtree
        let unrelated = TestShareBlockBuilder::new().nonce(99).build();
        let _unrelated_hash = unrelated.block_hash();
        let mut share_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(unrelated.block_hash().to_string())
            .nonce(3)
            .build()
            .header;
        share_c.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        // Anchor parent exists in store, unrelated parent does not
        chain_store_handle
            .expect_get_block_metadata()
            .returning(move |hash| {
                if *hash == anchor_hash {
                    Ok(BlockMetadata {
                        expected_height: Some(0),
                        chain_work: Work::from_hex("0x00").unwrap(),
                        status: Status::Confirmed,
                    })
                } else {
                    Err(StoreError::NotFound(format!("{hash} not found")))
                }
            });
        chain_store_handle
            .expect_get_block_metadata_batch()
            .returning(move |hashes| {
                hashes
                    .iter()
                    .filter(|hash| **hash == anchor_hash)
                    .map(|hash| {
                        (
                            *hash,
                            BlockMetadata {
                                expected_height: Some(0),
                                chain_work: Work::from_hex("0x00").unwrap(),
                                status: Status::Confirmed,
                            },
                        )
                    })
                    .collect()
            });
        let template_header = build_valid_test_header();
        chain_store_handle
            .expect_get_share_header()
            .returning(move |_| Ok(template_header.clone()));
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let headers = vec![share_a, share_c];
        let result = validate_header_chain(&headers, &chain_store_handle, &mock_validator);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not in batch or store"),
            "Expected 'not in batch or store' error for disconnected subtree"
        );
    }

    /// A fork from the anchor is valid DAG behavior -- it's a sibling
    /// branch that will be stored and may become an uncle later.
    #[test]
    fn test_validate_header_chain_accepts_fork_from_anchor() {
        let anchor = TestShareBlockBuilder::new().nonce(1).build();
        let mut share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        share_a.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .nonce(3)
            .build()
            .header;
        share_b.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut share_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_b.block_hash().to_string())
            .nonce(4)
            .build()
            .header;
        share_c.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        // share_d forks from anchor -- valid DAG member
        let mut share_d = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(5)
            .build()
            .header;
        share_d.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let headers = vec![share_a, share_b, share_c, share_d];
        let result = validate_header_chain(&headers, &chain_store_handle, &mock_validator);
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());
    }

    #[test]
    fn test_validate_header_chain_accepts_uncle_referencing_anchor() {
        let anchor = TestShareBlockBuilder::new().nonce(1).build();
        let mut share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        share_a.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .nonce(3)
            .build()
            .header;
        share_b.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        // uncle has parent=anchor, which remains in the recent_confirmed
        // window throughout this batch.
        let mut uncle = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(4)
            .build()
            .header;
        uncle.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut share_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_b.block_hash().to_string())
            .uncles(vec![uncle.block_hash()])
            .nonce(5)
            .build()
            .header;
        share_c.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let headers = vec![share_a, share_b, uncle, share_c];
        let result = validate_header_chain(&headers, &chain_store_handle, &mock_validator);
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());
    }

    #[test]
    fn test_validate_header_chain_accepts_uncle_subtree_before_nephew() {
        // Confirmed chain is A -> E -> H. B, C, D are HeaderValid uncles
        // (all parent=A) referenced by E. F, G are HeaderValid uncles (all
        // parent=E) referenced by H. Sync order: B, C, D, E, F, G, H.
        let anchor = TestShareBlockBuilder::new().nonce(1).build();

        let mut share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        share_b.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut share_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(3)
            .build()
            .header;
        share_c.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut share_d = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(4)
            .build()
            .header;
        share_d.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut share_e = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .uncles(vec![
                share_b.block_hash(),
                share_c.block_hash(),
                share_d.block_hash(),
            ])
            .nonce(5)
            .build()
            .header;
        share_e.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut share_f = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_e.block_hash().to_string())
            .nonce(6)
            .build()
            .header;
        share_f.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut share_g = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_e.block_hash().to_string())
            .nonce(7)
            .build()
            .header;
        share_g.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut share_h = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_e.block_hash().to_string())
            .uncles(vec![share_f.block_hash(), share_g.block_hash()])
            .nonce(8)
            .build()
            .header;
        share_h.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let headers = vec![
            share_b, share_c, share_d, share_e, share_f, share_g, share_h,
        ];
        let result = validate_header_chain(&headers, &chain_store_handle, &mock_validator);
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());
    }

    /// Reproduces a sync issue: uncle header declares a confirmed
    /// block as its own uncle. Previously collect_declared_uncles
    /// added the confirmed block to the uncle set, causing it to be
    /// skipped during chain-linkage validation, breaking sync.
    ///
    /// Scenario (from testnet4 debugging):
    ///   Confirmed chain: anchor -> A(h:1) -> B(h:2) -> C(h:3)
    ///   Fork: anchor -> fork_parent(h:1) -> U(h:2)
    ///   U declares A(h:1) as its own uncle (valid: A is at ancestor height).
    ///   C declares U as uncle.
    ///   Batch order: A, fork_parent, B, U, C
    ///
    /// Old behaviour: A is in declared_uncles (via U's .uncles), gets
    /// classified as uncle, B fails because parent A was skipped.
    /// New behaviour: DAG connectivity passes because all parents are
    /// in the batch or store.
    #[test]
    fn test_validate_header_chain_accepts_uncle_declaring_confirmed_block_as_its_uncle() {
        let anchor = TestShareBlockBuilder::new().nonce(1).build();

        // A: confirmed at h:1
        let mut share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        share_a.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        // fork_parent: fork block at h:1 (same parent as A)
        let mut fork_parent = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(3)
            .build()
            .header;
        fork_parent.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        // B: confirmed at h:2
        let mut share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .nonce(4)
            .build()
            .header;
        share_b.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        // U: uncle at h:2 (parent=fork_parent), declares A as its own uncle
        let mut uncle_u = TestShareBlockBuilder::new()
            .prev_share_blockhash(fork_parent.block_hash().to_string())
            .uncles(vec![share_a.block_hash()])
            .nonce(5)
            .build()
            .header;
        uncle_u.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        // C: confirmed at h:3, declares U as uncle
        let mut share_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_b.block_hash().to_string())
            .uncles(vec![uncle_u.block_hash()])
            .nonce(6)
            .build()
            .header;
        share_c.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        // Batch order: A, fork_parent, B, U, C
        let headers = vec![share_a, fork_parent, share_b, uncle_u, share_c];
        let result = validate_header_chain(&headers, &chain_store_handle, &mock_validator);
        assert!(result.is_ok(), "Expected Ok, got: {}", result.unwrap_err());
    }
}
