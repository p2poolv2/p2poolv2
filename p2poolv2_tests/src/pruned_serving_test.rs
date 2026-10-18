// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for what a node with pruned block bodies serves to a
//! peer syncing from genesis.
//!
//! These drive the real getheaders and getdata handlers against a real store
//! (no mocks). Each test confirms a chain, prunes the bodies below a height,
//! and checks the responses: headers and their coinbase merkle branches are
//! served for every height, bodies only above the pruned range.

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use p2poolv2_lib::node::SwarmSend;
use p2poolv2_lib::node::messages::{GetData, Message};
use p2poolv2_lib::node::p2p_message_handlers::receivers::getdata::handle_getdata_block;
use p2poolv2_lib::node::p2p_message_handlers::receivers::getheaders::handle_getheaders;
use p2poolv2_lib::test_utils::{build_confirmed_test_chain, setup_test_chain_store_handle};
use tokio::sync::mpsc;

/// Length of the confirmed chain built above genesis.
const CHAIN_LENGTH: usize = 20;

/// Bodies at heights below this are pruned; genesis is always kept.
const PRUNED_BELOW: u32 = 12;

/// A response channel stand-in; the handlers only pass it through.
const RESPONSE_CHANNEL: u32 = 1;

/// A peer syncing from genesis receives every header, pruned heights
/// included, each with the merkle branch of the original block.
#[tokio::test]
async fn test_pruned_node_serves_every_header_from_genesis() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
    let blocks = build_confirmed_test_chain(&chain_store_handle, CHAIN_LENGTH).await;
    chain_store_handle
        .prune_block_bodies(1, PRUNED_BELOW)
        .await
        .unwrap();
    let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);

    handle_getheaders(
        vec![blocks[0].block_hash()],
        BlockHash::all_zeros(),
        chain_store_handle,
        RESPONSE_CHANNEL,
        swarm_tx,
    )
    .await
    .unwrap();

    let Some(SwarmSend::Response(_, Message::ShareHeaders(batch))) = swarm_rx.recv().await else {
        panic!("expected a ShareHeaders response");
    };
    let served_hashes: Vec<BlockHash> = batch
        .headers()
        .iter()
        .map(|header| header.block_hash())
        .collect();
    let expected_hashes: Vec<BlockHash> =
        blocks[1..].iter().map(|block| block.block_hash()).collect();
    assert_eq!(served_hashes, expected_hashes);
    assert_eq!(batch.headers()[4], blocks[5].header);
    assert_eq!(
        batch.branch(4),
        blocks[5].template_merkle_branches.as_slice()
    );
    assert_eq!(
        batch.branch(CHAIN_LENGTH - 1),
        blocks[CHAIN_LENGTH].template_merkle_branches.as_slice()
    );
}

/// A body request for a pruned height gets NotFound, which the requesting
/// peer handles without penalising the server.
#[tokio::test]
async fn test_pruned_node_replies_not_found_for_pruned_body() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
    let blocks = build_confirmed_test_chain(&chain_store_handle, CHAIN_LENGTH).await;
    chain_store_handle
        .prune_block_bodies(1, PRUNED_BELOW)
        .await
        .unwrap();
    let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
    let pruned_hash = blocks[PRUNED_BELOW as usize - 1].block_hash();

    handle_getdata_block(pruned_hash, chain_store_handle, RESPONSE_CHANNEL, swarm_tx)
        .await
        .unwrap();

    let Some(SwarmSend::Response(_, Message::NotFound(GetData::Block(hash)))) =
        swarm_rx.recv().await
    else {
        panic!("expected a NotFound response");
    };
    assert_eq!(hash, pruned_hash);
}

/// A body request at the first kept height gets the original block.
#[tokio::test]
async fn test_pruned_node_serves_kept_body() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
    let blocks = build_confirmed_test_chain(&chain_store_handle, CHAIN_LENGTH).await;
    chain_store_handle
        .prune_block_bodies(1, PRUNED_BELOW)
        .await
        .unwrap();
    let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
    let kept_block = blocks[PRUNED_BELOW as usize].clone();

    handle_getdata_block(
        kept_block.block_hash(),
        chain_store_handle,
        RESPONSE_CHANNEL,
        swarm_tx,
    )
    .await
    .unwrap();

    let Some(SwarmSend::Response(_, Message::ShareBlock(share_block))) = swarm_rx.recv().await
    else {
        panic!("expected a ShareBlock response");
    };
    assert_eq!(share_block, kept_block);
}

/// The locator still names blocks at pruned heights after their candidate
/// index entries are deleted, by falling back to the confirmed index.
#[tokio::test]
async fn test_pruned_node_locator_resolves_pruned_heights() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
    let blocks = build_confirmed_test_chain(&chain_store_handle, CHAIN_LENGTH).await;
    chain_store_handle
        .prune_block_bodies(1, PRUNED_BELOW)
        .await
        .unwrap();

    let locator = chain_store_handle.build_locator(0).unwrap();

    // Heights 20 down to 11, then 10, 8 and 4 from the pruned range, then
    // genesis.
    let expected_locator = vec![
        blocks[20].block_hash(),
        blocks[19].block_hash(),
        blocks[18].block_hash(),
        blocks[17].block_hash(),
        blocks[16].block_hash(),
        blocks[15].block_hash(),
        blocks[14].block_hash(),
        blocks[13].block_hash(),
        blocks[12].block_hash(),
        blocks[11].block_hash(),
        blocks[10].block_hash(),
        blocks[8].block_hash(),
        blocks[4].block_hash(),
        blocks[0].block_hash(),
    ];
    assert!(chain_store_handle.get_candidate_at_height(8).is_err());
    assert_eq!(locator, expected_locator);
}
