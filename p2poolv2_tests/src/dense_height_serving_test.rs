// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Integration tests for serving header sync across a dense height.
//!
//! These drive the real getheaders handler against a real store (no mocks).
//! Each test builds a height holding more than `MAX_BLOCKS_PER_HEIGHT`
//! blocks, where the confirmed block has the largest hash, and checks what a
//! 1.1.0 and a 1.0.0 requester are served.

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use p2poolv2_lib::node::SwarmSend;
use p2poolv2_lib::node::behaviour::request_response::ProtocolVersion;
use p2poolv2_lib::node::messages::{GetShareHeaders, Message};
use p2poolv2_lib::node::p2p_message_handlers::receivers::getheaders::handle_getheaders;
use p2poolv2_lib::shares::share_block::ShareBlock;
use p2poolv2_lib::test_utils::{
    TestShareBlockBuilder, confirm_test_block, genesis_for_tests, setup_test_chain_store_handle,
};
use tokio::sync::mpsc;

/// Blocks mined on genesis at height 1, more than the 1.0.0 per-height cap.
const DENSE_HEIGHT_BLOCKS: u32 = 26;

/// A response channel stand-in; the handler only passes it through.
const RESPONSE_CHANNEL: u32 = 1;

/// A 1.1.0 requester syncing from genesis receives every block at the dense
/// height, including the confirmed block the 1.0.0 cap would drop, and the
/// confirmed child built on it.
#[tokio::test]
async fn test_v1_1_request_serves_confirmed_block_at_dense_height() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
    let genesis = genesis_for_tests();
    chain_store_handle
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    //* Mine the dense height. The block with the largest hash is confirmed;
    //* the rest arrive as headers only, as header sync stores them.
    let mut siblings: Vec<ShareBlock> = (1..=DENSE_HEIGHT_BLOCKS)
        .map(|nonce| {
            TestShareBlockBuilder::new()
                .prev_share_blockhash(genesis.block_hash().to_string())
                .nonce(nonce)
                .build()
        })
        .collect();
    siblings.sort_by_key(|block| block.block_hash());
    let chain_block = siblings.pop().unwrap();
    confirm_test_block(&chain_store_handle, &chain_block).await;
    for sibling in &siblings {
        chain_store_handle
            .organise_header(sibling.header.clone())
            .await
            .unwrap();
    }
    let child = TestShareBlockBuilder::new()
        .prev_share_blockhash(chain_block.block_hash().to_string())
        .nonce(1000)
        .build();
    confirm_test_block(&chain_store_handle, &child).await;
    let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);

    handle_getheaders(
        GetShareHeaders::new(vec![genesis.block_hash()], BlockHash::all_zeros(), None),
        chain_store_handle,
        RESPONSE_CHANNEL,
        swarm_tx,
    )
    .await
    .unwrap();

    let Some(SwarmSend::Response(_, Message::ShareHeaders(batch))) = swarm_rx.recv().await else {
        panic!("expected a ShareHeaders response");
    };
    let served: Vec<BlockHash> = batch
        .headers()
        .iter()
        .map(|header| header.block_hash())
        .collect();
    //* Height 1 ascending by hash with the chain block last, then the child.
    let mut expected: Vec<BlockHash> = siblings.iter().map(|block| block.block_hash()).collect();
    expected.push(chain_block.block_hash());
    expected.push(child.block_hash());
    assert_eq!(served, expected);
}

/// A 1.0.0 requester is still served the legacy way: the dense height is
/// truncated, so the confirmed block is missing while its child is served.
/// That is what a v0.18 receiver expects, and why it needs the 1.1.0
/// protocol to sync past a dense height.
#[tokio::test]
async fn test_v1_0_request_truncates_dense_height() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
    let genesis = genesis_for_tests();
    chain_store_handle
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    //* Mine the dense height. The block with the largest hash is confirmed;
    //* the rest arrive as headers only, as header sync stores them.
    let mut siblings: Vec<ShareBlock> = (1..=DENSE_HEIGHT_BLOCKS)
        .map(|nonce| {
            TestShareBlockBuilder::new()
                .prev_share_blockhash(genesis.block_hash().to_string())
                .nonce(nonce)
                .build()
        })
        .collect();
    siblings.sort_by_key(|block| block.block_hash());
    let chain_block = siblings.pop().unwrap();
    confirm_test_block(&chain_store_handle, &chain_block).await;
    for sibling in &siblings {
        chain_store_handle
            .organise_header(sibling.header.clone())
            .await
            .unwrap();
    }
    let child = TestShareBlockBuilder::new()
        .prev_share_blockhash(chain_block.block_hash().to_string())
        .nonce(1000)
        .build();
    confirm_test_block(&chain_store_handle, &child).await;
    let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);

    let request = GetShareHeaders {
        locator: vec![genesis.block_hash()],
        stop: BlockHash::all_zeros(),
        resume_after: None,
        protocol_version: ProtocolVersion::V1_0,
    };
    handle_getheaders(request, chain_store_handle, RESPONSE_CHANNEL, swarm_tx)
        .await
        .unwrap();

    let Some(SwarmSend::Response(_, Message::ShareHeaders(batch))) = swarm_rx.recv().await else {
        panic!("expected a ShareHeaders response");
    };
    let served: Vec<BlockHash> = batch
        .headers()
        .iter()
        .map(|header| header.block_hash())
        .collect();
    assert!(!served.contains(&chain_block.block_hash()));
    assert!(served.contains(&child.block_hash()));
}
