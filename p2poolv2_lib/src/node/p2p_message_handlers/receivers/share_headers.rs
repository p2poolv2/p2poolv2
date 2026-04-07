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
use crate::store::dag_store::MAX_UNCLES_DEPTH;
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Target, Work};
use std::collections::{HashMap, HashSet, VecDeque};
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

/// Validate the received header batch.
///
/// The batch may contain both confirmed chain headers and uncle headers
/// (interleaved by get_descendant_blockhashes). All headers must pass
/// minimum difficulty. Confirmed chain headers (those that link via
/// prev_share_blockhash) are additionally ASERT-validated.
///
/// Checks performed:
/// 1. Every header passes validate_header_minimum_difficulty
/// 2. Every header's prev_share_blockhash references the anchor or another header in the batch
/// 3. Confirmed chain headers have bits matching ASERT-computed target
/// 4. Cumulative work of confirmed chain exceeds MIN_CUMULATIVE_CHAIN_WORK
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
    let anchor_header = chain_store_handle.get_share_header(&anchor_hash)?;

    let declared_uncles = collect_declared_uncles(share_headers);
    let (recent_confirmed, parent_info) = seed_from_store(
        anchor_hash,
        &anchor_header,
        &anchor_metadata,
        chain_store_handle,
    )?;
    let (confirmed_chain, cumulative_chain_work, uncle_headers_seen) = classify_link_and_validate(
        share_headers,
        recent_confirmed,
        parent_info,
        &declared_uncles,
        share_validator,
        pool_difficulty,
    )?;
    verify_have_all_uncles(&confirmed_chain, &uncle_headers_seen, chain_store_handle)?;
    validate_cumulative_work(anchor_metadata.chain_work, cumulative_chain_work)?;

    debug!(
        "Validated {} headers ({} confirmed chain), cumulative chain work: {cumulative_chain_work}",
        share_headers.len(),
        confirmed_chain.len()
    );
    Ok(())
}

/// Build the set of all blockhashes declared as uncles by any header in the batch.
fn collect_declared_uncles(share_headers: &[ShareHeader]) -> HashSet<BlockHash> {
    let mut declared = HashSet::with_capacity(share_headers.len() * MAX_UNCLES_DEPTH as usize);
    for header in share_headers {
        for uncle_hash in &header.uncles {
            declared.insert(*uncle_hash);
        }
    }
    declared
}

/// Seed the recent confirmed window and parent_info map from the store.
///
/// Walks up to MAX_UNCLES_DEPTH ancestors from the anchor via prev_share_blockhash,
/// stopping early at genesis or on lookup error. The returned VecDeque contains
/// older ancestors first with the anchor at the back. parent_info maps each
/// seeded hash to its (time, height) so ASERT can be evaluated against any
/// header whose parent is one of the seeded ancestors.
fn seed_from_store(
    anchor_hash: BlockHash,
    anchor_header: &ShareHeader,
    anchor_metadata: &crate::store::block_tx_metadata::BlockMetadata,
    chain_store_handle: &ChainStoreHandle,
) -> Result<(VecDeque<BlockHash>, HashMap<BlockHash, (u32, u32)>), Box<dyn Error + Send + Sync>> {
    let capacity = MAX_UNCLES_DEPTH as usize + 1;
    let mut recent_confirmed: VecDeque<BlockHash> = VecDeque::with_capacity(capacity);
    let mut parent_info: HashMap<BlockHash, (u32, u32)> = HashMap::with_capacity(capacity);

    let anchor_height = anchor_metadata
        .expected_height
        .ok_or_else(|| format!("Anchor {anchor_hash} metadata has no expected_height"))?;
    recent_confirmed.push_back(anchor_hash);
    parent_info.insert(anchor_hash, (anchor_header.time, anchor_height));

    let mut current_hash = anchor_header.prev_share_blockhash;
    let mut current_height = anchor_height;
    let mut iterations: u8 = 0;
    while current_height > 0 && iterations < MAX_UNCLES_DEPTH {
        let header = chain_store_handle
            .get_share_header(&current_hash)
            .map_err(|store_error| {
                format!("Failed to load ancestor {current_hash} from store: {store_error}")
            })?;
        current_height -= 1;
        recent_confirmed.push_front(current_hash);
        parent_info.insert(current_hash, (header.time, current_height));
        current_hash = header.prev_share_blockhash;
        iterations += 1;
    }

    Ok((recent_confirmed, parent_info))
}

/// Walk the batch in order, classifying each header as uncle or confirmed,
/// validating min PoW and ASERT for every header, and enforcing chain linkage.
///
/// Returns the confirmed chain and the cumulative work contributed by it.
fn classify_link_and_validate<'a>(
    share_headers: &'a [ShareHeader],
    mut recent_confirmed: VecDeque<BlockHash>,
    mut parent_info: HashMap<BlockHash, (u32, u32)>,
    declared_uncles: &HashSet<BlockHash>,
    share_validator: &(dyn ShareValidator + Send + Sync),
    pool_difficulty: &PoolDifficulty,
) -> Result<(Vec<&'a ShareHeader>, Work, HashSet<BlockHash>), Box<dyn Error + Send + Sync>> {
    let window_capacity = MAX_UNCLES_DEPTH as usize + 1;
    let mut confirmed_chain: Vec<&ShareHeader> = Vec::with_capacity(share_headers.len());
    let mut confirmed_tip: BlockHash = *recent_confirmed.back().unwrap();
    let mut cumulative_chain_work = Work::from_hex("0x00").unwrap();
    let mut uncle_headers_seen: HashSet<BlockHash> = HashSet::with_capacity(share_headers.len());

    for (index, header) in share_headers.iter().enumerate() {
        share_validator.validate_header_minimum_difficulty(header)?;

        let (parent_time, parent_height) = match parent_info.get(&header.prev_share_blockhash) {
            Some(value) => *value,
            None => {
                return Err(format!(
                    "Header {} at position {} has parent {} which is not in the recent confirmed window",
                    header.block_hash(),
                    index,
                    header.prev_share_blockhash
                )
                .into());
            }
        };

        let expected_bits = pool_difficulty.calculate_target_clamped(
            parent_time,
            parent_height,
            header.bitcoin_header.bits,
        );
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
        if declared_uncles.contains(&header_hash) {
            // Uncle: ASERT validated above; do not extend the confirmed chain.
            uncle_headers_seen.insert(header_hash);
            continue;
        }

        // Confirmed: must extend the current tip.
        if header.prev_share_blockhash != confirmed_tip {
            return Err(format!(
                "Header {} at position {} has parent {} which is not the chain tip {}",
                header_hash, index, header.prev_share_blockhash, confirmed_tip
            )
            .into());
        }

        confirmed_chain.push(header);
        cumulative_chain_work = cumulative_chain_work + header.get_work();
        confirmed_tip = header_hash;
        recent_confirmed.push_back(header_hash);
        if recent_confirmed.len() > window_capacity {
            recent_confirmed.pop_front();
        }
        parent_info.insert(header_hash, (header.time, parent_height + 1));
    }

    Ok((confirmed_chain, cumulative_chain_work, uncle_headers_seen))
}

/// Verify every uncle hash declared by a confirmed header was either delivered
/// in this batch (and thus already validated in classify_link_and_validate) or
/// is already organised in the store from an earlier batch. Catches phantom
/// uncle references that no peer ever sent.
fn verify_have_all_uncles(
    confirmed_chain: &[&ShareHeader],
    uncle_headers_seen: &HashSet<BlockHash>,
    chain_store_handle: &ChainStoreHandle,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    for confirmed in confirmed_chain {
        for uncle_hash in &confirmed.uncles {
            if !uncle_headers_seen.contains(uncle_hash)
                && !chain_store_handle.share_block_exists(uncle_hash)
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

/// Find the chain anchor: the first parent hash from the batch that exists
/// in our store. Returns the anchor blockhash and its metadata.
fn find_chain_anchor(
    share_headers: &[ShareHeader],
    chain_store_handle: &ChainStoreHandle,
) -> Result<(BlockHash, crate::store::block_tx_metadata::BlockMetadata), Box<dyn Error + Send + Sync>>
{
    let parent_candidates: Vec<BlockHash> = share_headers
        .iter()
        .map(|header| header.prev_share_blockhash)
        .collect();
    let anchor_hash = chain_store_handle
        .first_existing_share_header(&parent_candidates)
        .ok_or("No header in batch has a parent in the store")?;
    let anchor_metadata = chain_store_handle
        .get_block_metadata(&anchor_hash)
        .map_err(|_| format!("Anchor {anchor_hash} metadata not found"))?;
    Ok((anchor_hash, anchor_metadata))
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
        chain_store_handle
            .expect_first_existing_share_header()
            .returning(|hashes| hashes.first().copied());
    }

    fn setup_minimum_difficulty_mock(mock_validator: &mut MockDefaultShareValidator) {
        mock_validator
            .expect_validate_header_minimum_difficulty()
            .returning(|_| Ok(()));
        let mut pool_difficulty = PoolDifficulty::default();
        pool_difficulty
            .expect_calculate_target_clamped()
            .returning(|_, _, _| CompactTarget::from_consensus(MAX_POOL_TARGET));
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
            .expect_first_existing_share_header()
            .returning(|_| None);
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
        let mut share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        share_a.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        // share_c has an unrelated parent, forming a disconnected subtree
        let unrelated = TestShareBlockBuilder::new().nonce(99).build();
        let mut share_c = TestShareBlockBuilder::new()
            .prev_share_blockhash(unrelated.block_hash().to_string())
            .nonce(3)
            .build()
            .header;
        share_c.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let headers = vec![share_a, share_c];
        let result = validate_header_chain(&headers, &chain_store_handle, &mock_validator);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not in the recent confirmed window"),
        );
    }

    #[test]
    fn test_validate_header_chain_rejects_share_d_branching_off_anchor() {
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
        // share_d forks from anchor; with no header declaring it as an
        // uncle, the classifier treats it as a confirmed candidate that
        // does not extend the tip and rejects it.
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
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not the chain tip"),
        );
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

    #[test]
    fn test_validate_header_chain_rejects_unreferenced_uncle() {
        let anchor = TestShareBlockBuilder::new().nonce(1).build();
        let mut share_a = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(2)
            .build()
            .header;
        share_a.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        // uncle has a valid parent (anchor) but no confirmed header
        // in the batch lists it in its uncles field
        let mut unreferenced_uncle = TestShareBlockBuilder::new()
            .prev_share_blockhash(anchor.block_hash().to_string())
            .nonce(3)
            .build()
            .header;
        unreferenced_uncle.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);
        let mut share_b = TestShareBlockBuilder::new()
            .prev_share_blockhash(share_a.block_hash().to_string())
            .nonce(4)
            .build()
            .header;
        share_b.bits = CompactTarget::from_consensus(MAX_POOL_TARGET);

        let mut chain_store_handle = ChainStoreHandle::default();
        setup_chain_validation_mocks(&mut chain_store_handle);
        let mut mock_validator = MockDefaultShareValidator::default();
        setup_minimum_difficulty_mock(&mut mock_validator);

        let headers = vec![share_a, unreferenced_uncle, share_b];
        let result = validate_header_chain(&headers, &chain_store_handle, &mock_validator);
        assert!(result.is_err());
        // With the uncles[]-driven classifier, an "uncle" that no header
        // references is indistinguishable from a confirmed header that does
        // not extend the tip, so it is rejected via the chain-tip check.
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not the chain tip"),
        );
    }
}
