// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::node::Message;
use crate::node::SwarmSend;
use crate::node::behaviour::request_response::ProtocolVersion;
use crate::node::messages::{GetShareHeaders, ShareHeaderBatch};
use crate::node::p2p_message_handlers::MAX_HEADERS_IN_RESPONSE;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::debug;

/// Handle a GetHeaders request from a peer
/// - serve in the form the requester's protocol version understands:
///   - 1.0.0: headers after the locator, each height truncated to
///     MAX_BLOCKS_PER_HEIGHT, as v0.18 receivers expect
///   - 1.1.0: every header after `resume_after` (or after the locator), with
///     no per-height cap, paged mid-height when a page fills
/// - stop at the stop block hash and limit to MAX_HEADERS_IN_RESPONSE blocks
/// - respond with all headers found, each with the stored coinbase merkle
///   branch its proof is checked against
pub async fn handle_getheaders<C: Send + Sync>(
    request: GetShareHeaders,
    chain_store_handle: ChainStoreHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received GetHeaders: {:?}", request);
    let response_headers = match request.protocol_version {
        ProtocolVersion::V1_0 => chain_store_handle.get_headers_for_locator(
            &request.locator,
            &request.stop,
            MAX_HEADERS_IN_RESPONSE,
        )?,
        ProtocolVersion::V1_1 => chain_store_handle.get_headers_after(
            &request.locator,
            request.resume_after,
            &request.stop,
            MAX_HEADERS_IN_RESPONSE,
        )?,
    };
    let mut entries = Vec::with_capacity(response_headers.len());
    for header in response_headers {
        let branch = chain_store_handle.get_template_merkle_branches(&header.block_hash())?;
        entries.push((header, branch));
    }
    let headers_message =
        Message::ShareHeaders(ShareHeaderBatch::from_headers_with_branches(entries));
    // Send response and handle errors by logging them before returning
    debug!("Sending Headers {headers_message:?}");
    if let Err(err) = swarm_tx
        .send(SwarmSend::Response(response_channel, headers_message))
        .await
    {
        tracing::error!("Failed to send getheaders response: {}", err);
        return Err(format!("Failed to send getheaders response: {err}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::test_utils::TestShareBlockBuilder;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use tokio::sync::mpsc;

    /// A request from a 1.0.0 peer is served from the locator by the legacy
    /// walk, never the 1.1.0 one, whose uncapped heights the old receiver
    /// would reject.
    #[tokio::test]
    async fn test_handle_getheaders_v1_0_request_serves_from_locator() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;

        let block1 = TestShareBlockBuilder::new().build();

        let block2 = TestShareBlockBuilder::new().build();

        let block_hashes = vec![block1.block_hash(), block2.block_hash()];

        let response_headers = vec![block1.header.clone(), block2.header.clone()];

        let stop_block_hash = block2.block_hash();

        // Set up mock expectations
        chain_store_handle
            .expect_get_headers_for_locator()
            .times(1)
            .returning(move |_, _, _| Ok(response_headers.clone()));
        chain_store_handle
            .expect_get_template_merkle_branches()
            .returning(|_| Ok(Vec::new()));

        let request = GetShareHeaders {
            locator: block_hashes,
            stop: stop_block_hash,
            resume_after: None,
            protocol_version: ProtocolVersion::V1_0,
        };
        let _result =
            handle_getheaders(request, chain_store_handle, response_channel, swarm_tx).await;

        // Verify swarm message
        if let Some(SwarmSend::Response(channel, Message::ShareHeaders(headers))) =
            swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(
                headers.headers().to_vec(),
                vec![block1.header, block2.header]
            );
        } else {
            panic!("Expected SwarmSend::Response with ShareHeaders message");
        }
    }

    /// Each served header carries its stored coinbase branch, and headers
    /// sharing a branch share one table entry.
    #[tokio::test]
    async fn test_handle_getheaders_serves_stored_branches() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);

        let block1 = TestShareBlockBuilder::new().nonce(1).build();
        let block2 = TestShareBlockBuilder::new().nonce(2).build();
        let response_headers = vec![block1.header.clone(), block2.header.clone()];
        let branch = vec![bitcoin::TxMerkleNode::from_byte_array([0x42; 32])];
        let stored_branch = branch.clone();

        chain_store_handle
            .expect_get_headers_after()
            .returning(move |_, _, _, _| Ok(response_headers.clone()));
        chain_store_handle
            .expect_get_template_merkle_branches()
            .times(2)
            .returning(move |_| Ok(stored_branch.clone()));

        handle_getheaders(
            GetShareHeaders::new(vec![block1.block_hash()], block2.block_hash(), None),
            chain_store_handle,
            1u32,
            swarm_tx,
        )
        .await
        .unwrap();

        match swarm_rx.recv().await {
            Some(SwarmSend::Response(_, Message::ShareHeaders(batch))) => {
                assert_eq!(batch.len(), 2);
                assert_eq!(batch.branch_count(), 1);
                assert_eq!(batch.branch(0), branch.as_slice());
                assert_eq!(batch.branch(1), branch.as_slice());
            }
            _ => panic!("Expected SwarmSend::Response with ShareHeaders message"),
        }
    }

    /// A request from a 1.1.0 peer is served by the uncapped walk, with the
    /// requester's resume point, locator and stop passed through unchanged.
    #[tokio::test]
    async fn test_handle_getheaders_v1_1_request_passes_resume_point() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);

        let locator_block = TestShareBlockBuilder::new().nonce(1).build();
        let resume_block = TestShareBlockBuilder::new().nonce(2).build();
        let served_block = TestShareBlockBuilder::new().nonce(3).build();
        let locator = vec![locator_block.block_hash()];
        let resume_hash = resume_block.block_hash();
        let response_headers = vec![served_block.header.clone()];

        let expected_locator = locator.clone();
        chain_store_handle
            .expect_get_headers_after()
            .withf(move |requested_locator, resume_after, stop, limit| {
                requested_locator == expected_locator.as_slice()
                    && *resume_after == Some(resume_hash)
                    && *stop == BlockHash::all_zeros()
                    && *limit == MAX_HEADERS_IN_RESPONSE
            })
            .times(1)
            .returning(move |_, _, _, _| Ok(response_headers.clone()));
        chain_store_handle
            .expect_get_template_merkle_branches()
            .returning(|_| Ok(Vec::new()));

        let request = GetShareHeaders::new(locator, BlockHash::all_zeros(), Some(resume_hash));
        handle_getheaders(request, chain_store_handle, 1u32, swarm_tx)
            .await
            .unwrap();

        match swarm_rx.recv().await {
            Some(SwarmSend::Response(_, Message::ShareHeaders(batch))) => {
                assert_eq!(batch.headers().to_vec(), vec![served_block.header]);
            }
            _ => panic!("Expected SwarmSend::Response with ShareHeaders message"),
        }
    }

    #[tokio::test]
    async fn test_handle_getheaders_send_failure() {
        let mut chain_store_handle = ChainStoreHandle::default();
        let (swarm_tx, swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;

        let block1 = TestShareBlockBuilder::new().build();

        let block2 = TestShareBlockBuilder::new().build();

        let block_hashes = vec![block1.block_hash(), block2.block_hash()];

        let stop_block_hash = block2.block_hash();

        // Set up mock expectations
        chain_store_handle
            .expect_get_headers_after()
            .returning(move |_, _, _, _| Ok(Vec::new()));
        chain_store_handle
            .expect_get_template_merkle_branches()
            .returning(|_| Ok(Vec::new()));

        // Drop the receiver to simulate send failure
        drop(swarm_rx);

        let result = handle_getheaders(
            GetShareHeaders::new(block_hashes, stop_block_hash, None),
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Failed to send getheaders response"));
        } else {
            panic!("Expected an error due to send failure");
        }
    }
}
