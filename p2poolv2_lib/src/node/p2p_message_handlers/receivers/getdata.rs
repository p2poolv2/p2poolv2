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

use crate::node::Message;
use crate::node::SwarmSend;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use bitcoin::BlockHash;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Handle a GetData::Block request from a peer.
///
/// Looks up the requested block and responds with the full ShareBlock if
/// the block is confirmed or is an uncle of a confirmed block. Otherwise
/// responds with NotFound, following bitcoin protocol 70001 semantics.
pub async fn handle_getdata_block<C: Send + Sync>(
    block_hash: BlockHash,
    chain_store_handle: ChainStoreHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Handling getdata block request for {}", block_hash);

    let response_message = match chain_store_handle.get_share(&block_hash) {
        Some(share_block) if chain_store_handle.is_confirmed_or_confirmed_uncle(&block_hash) => {
            info!("Serving block {} to peer", block_hash);
            Message::ShareBlock(share_block)
        }
        Some(_) => {
            info!(
                "Block {} exists but is not confirmed or uncle of confirmed, sending notfound",
                block_hash
            );
            Message::NotFound(())
        }
        None => {
            info!("Block {} not found, sending notfound", block_hash);
            Message::NotFound(())
        }
    };

    if let Err(err) = swarm_tx
        .send(SwarmSend::Response(response_channel, response_message))
        .await
    {
        tracing::error!("Failed to send getdata block response: {}", err);
        return Err(format!("Failed to send getdata block response: {err}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;
    use crate::test_utils::TestShareBlockBuilder;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_getdata_block_confirmed() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let block = TestShareBlockBuilder::new().build();
        let block_hash = block.block_hash();
        let expected_block = block.clone();

        chain_store_handle
            .expect_get_share()
            .returning(move |_| Some(block.clone()));
        chain_store_handle
            .expect_is_confirmed_or_confirmed_uncle()
            .returning(|_| true);

        let result =
            handle_getdata_block(block_hash, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_ok());

        if let Some(SwarmSend::Response(channel, Message::ShareBlock(share_block))) =
            swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(share_block, expected_block);
        } else {
            panic!("Expected SwarmSend::Response with ShareBlock message");
        }
    }

    #[tokio::test]
    async fn test_handle_getdata_block_not_confirmed() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let block = TestShareBlockBuilder::new().build();
        let block_hash = block.block_hash();

        chain_store_handle
            .expect_get_share()
            .returning(move |_| Some(block.clone()));
        chain_store_handle
            .expect_is_confirmed_or_confirmed_uncle()
            .returning(|_| false);

        let result =
            handle_getdata_block(block_hash, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_ok());

        if let Some(SwarmSend::Response(channel, Message::NotFound(()))) = swarm_rx.recv().await {
            assert_eq!(channel, response_channel);
        } else {
            panic!("Expected SwarmSend::Response with NotFound message");
        }
    }

    #[tokio::test]
    async fn test_handle_getdata_block_not_found() {
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let block_hash = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<BlockHash>()
            .unwrap();

        chain_store_handle.expect_get_share().returning(|_| None);

        let result =
            handle_getdata_block(block_hash, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_ok());

        if let Some(SwarmSend::Response(channel, Message::NotFound(()))) = swarm_rx.recv().await {
            assert_eq!(channel, response_channel);
        } else {
            panic!("Expected SwarmSend::Response with NotFound message");
        }
    }

    #[tokio::test]
    async fn test_handle_getdata_block_send_failure() {
        let (swarm_tx, swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;
        let mut chain_store_handle = ChainStoreHandle::default();

        let block_hash = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse::<BlockHash>()
            .unwrap();

        chain_store_handle.expect_get_share().returning(|_| None);

        // Drop receiver to cause send failure
        drop(swarm_rx);

        let result =
            handle_getdata_block(block_hash, chain_store_handle, response_channel, swarm_tx).await;

        assert!(result.is_err());
        if let Err(error) = result {
            assert!(
                error
                    .to_string()
                    .contains("Failed to send getdata block response")
            );
        }
    }
}
