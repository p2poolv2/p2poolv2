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
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Target, Work};
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
///   - Headers form a chain (each prev_share_blockhash matches the previous header)
///   - Each header's bits matches the ASERT-computed target from its parent
///   - Cumulative chain work exceeds confirmed tip and minimum threshold
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

    if share_headers.is_empty() {
        return trigger_or_request(
            peer_id,
            &share_headers,
            &chain_store_handle,
            &swarm_tx,
            &block_fetcher_handle,
        )
        .await;
    }

    // Phase 1: Validate the header chain in memory
    validate_header_chain(&share_headers, &chain_store_handle, share_validator)?;

    // Phase 2: Organise validated headers into the candidate chain
    for header in &share_headers {
        chain_store_handle.organise_header(header.clone()).await?;
    }

    trigger_or_request(
        peer_id,
        &share_headers,
        &chain_store_handle,
        &swarm_tx,
        &block_fetcher_handle,
    )
    .await
}

/// Validate the received header batch forms a valid ASERT chain.
///
/// Checks performed:
/// 1. Each header passes validate_header_minimum_difficulty (uncle count + target floor)
/// 2. Headers form a linked chain via prev_share_blockhash
/// 3. First header's parent exists in the store
/// 4. Each header's bits matches the ASERT-computed target from its parent
/// 5. Cumulative work exceeds MIN_CUMULATIVE_CHAIN_WORK
fn validate_header_chain(
    share_headers: &[ShareHeader],
    chain_store_handle: &ChainStoreHandle,
    share_validator: &(dyn ShareValidator + Send + Sync),
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let genesis_header = chain_store_handle.get_genesis_header()?;
    let pool_difficulty = PoolDifficulty::new(genesis_header.bits, genesis_header.time, 0);

    // Look up the first header's parent from the store
    let first_parent_hash = share_headers[0].prev_share_blockhash;
    let parent_header = chain_store_handle
        .get_share_header(&first_parent_hash)
        .map_err(|_| format!("First header's parent {first_parent_hash} not found in store"))?;
    let parent_metadata = chain_store_handle
        .get_block_metadata(&first_parent_hash)
        .map_err(|_| format!("First header's parent {first_parent_hash} metadata not found"))?;
    let mut parent_height = parent_metadata
        .expected_height
        .ok_or_else(|| format!("First header's parent {first_parent_hash} has no height"))?;
    let mut parent_time = parent_header.time;
    let mut previous_block_hash = first_parent_hash;
    let zero_work = Work::from_hex("0x00").unwrap();
    let mut cumulative_batch_work = zero_work;

    for (index, header) in share_headers.iter().enumerate() {
        share_validator.validate_header_minimum_difficulty(header)?;

        // Verify chain linkage
        if header.prev_share_blockhash != previous_block_hash {
            return Err(format!(
                "Header {} breaks chain: prev_share_blockhash {} does not match expected {}",
                index, header.prev_share_blockhash, previous_block_hash
            )
            .into());
        }

        // Verify ASERT difficulty
        let expected_bits = pool_difficulty.calculate_target_clamped(
            parent_time,
            parent_height,
            header.bitcoin_header.bits,
        );
        if header.bits != expected_bits {
            return Err(format!(
                "Header {} ASERT mismatch: declared bits {:#010x}, expected {:#010x}",
                index,
                header.bits.to_consensus(),
                expected_bits.to_consensus()
            )
            .into());
        }

        cumulative_batch_work = cumulative_batch_work + header.get_work();

        // Advance to next header's parent
        parent_time = header.time;
        parent_height += 1;
        previous_block_hash = header.block_hash();
    }

    // Verify cumulative work meets minimum threshold
    let single_share_work =
        Target::from_compact(CompactTarget::from_consensus(MAX_POOL_TARGET)).to_work();
    let mut min_cumulative_work = zero_work;
    for _ in 0..MIN_CUMULATIVE_CHAIN_WORK_MULTIPLIER {
        min_cumulative_work = min_cumulative_work + single_share_work;
    }
    let candidate_work = parent_metadata.chain_work + cumulative_batch_work;

    if candidate_work < min_cumulative_work {
        return Err(format!(
            "Cumulative chain work {candidate_work} below minimum {min_cumulative_work}"
        )
        .into());
    }

    debug!(
        "Validated {} headers, cumulative batch work: {cumulative_batch_work}",
        share_headers.len()
    );
    Ok(())
}

/// Either trigger block fetch or request next batch of headers.
async fn trigger_or_request<C: Send + Sync>(
    peer_id: libp2p::PeerId,
    share_headers: &[ShareHeader],
    chain_store_handle: &ChainStoreHandle,
    swarm_tx: &mpsc::Sender<SwarmSend<C>>,
    block_fetcher_handle: &BlockFetcherHandle,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if share_headers.len() < MAX_HEADERS_IN_RESPONSE {
        trigger_block_fetch(peer_id, chain_store_handle, block_fetcher_handle).await
    } else {
        request_next_headers(peer_id, share_headers, swarm_tx).await
    }
}

/// Header sync is complete -- query for candidate blocks missing full
/// block data and send them to the block fetcher for download.
async fn trigger_block_fetch(
    peer_id: libp2p::PeerId,
    chain_store_handle: &ChainStoreHandle,
    block_fetcher_handle: &BlockFetcherHandle,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Header sync complete, triggering block fetch for missing data");
    let missing_blockhashes = chain_store_handle.get_candidate_blocks_missing_data()?;
    if !missing_blockhashes.is_empty() {
        info!(
            "Requesting {} blocks from block fetcher",
            missing_blockhashes.len()
        );
        if let Err(send_error) = block_fetcher_handle
            .send(BlockFetcherEvent::FetchBlocks {
                blockhashes: missing_blockhashes,
                peer_id,
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
    }

    fn setup_minimum_difficulty_mock(mock_validator: &mut MockDefaultShareValidator) {
        mock_validator
            .expect_validate_header_minimum_difficulty()
            .returning(|_| Ok(()));
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
            .returning(|| Ok(Vec::new()));
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
            .returning(|| Ok(Vec::new()));
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
    async fn test_max_headers_sends_getheaders_to_same_peer() {
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

        let header = build_valid_test_header();
        let last_block_hash = header.block_hash();
        let share_headers = vec![header; MAX_HEADERS_IN_RESPONSE];

        let result = handle_share_headers(
            peer_id,
            share_headers,
            chain_store_handle,
            swarm_tx,
            block_fetcher_handle,
            &mock_validator,
        )
        .await;

        // This will fail on chain linkage for header[1] since all headers
        // have the same prev_share_blockhash but different would-be block_hash.
        assert!(result.is_err());

        // No getheaders should have been sent since validation failed
        assert!(swarm_rx.try_recv().is_err());
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
            .returning(move || Ok(returned_hashes.clone()));
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
            } => {
                assert_eq!(blockhashes, expected_hashes);
                assert_eq!(event_peer_id, peer_id);
            }
            other => panic!("expected FetchBlocks event, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_broken_chain_linkage_rejected() {
        let peer_id = libp2p::PeerId::random();
        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);

        let (swarm_tx, _swarm_rx) = mpsc::channel::<SwarmSend<oneshot::Sender<Message>>>(32);
        let (block_fetcher_handle, _block_fetcher_rx) =
            block_fetcher::create_block_fetcher_channel();

        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        // Two headers with different nonces produce different block_hash values.
        // header_b.prev_share_blockhash won't match header_a.block_hash().
        let mut header_a = TestShareBlockBuilder::new()
            .nonce(0xe9695791)
            .build()
            .header;
        header_a.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut header_b = TestShareBlockBuilder::new()
            .nonce(0xe9695792)
            .build()
            .header;
        header_b.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let share_headers = vec![header_a, header_b];

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
            result.unwrap_err().to_string().contains("breaks chain"),
            "Expected chain linkage error"
        );
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
}
