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
use tracing::debug;

const MAX_HEADERS: usize = 2000;

/// Handle a GetHeaders request from a peer
/// - start from chain tip, find blockhashes up to the stop block hash
/// - limit the number of blocks to MAX_HEADERS
/// - respond with send all headers found
pub async fn handle_getheaders<C: Send + Sync>(
    block_hashes: Vec<BlockHash>,
    stop_block_hash: BlockHash,
    chain_store_handle: ChainStoreHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    debug!("Received getheaders: {:?}", block_hashes);
    let response_headers =
        chain_store_handle.get_headers_for_locator(&block_hashes, &stop_block_hash, MAX_HEADERS)?;
    let headers_message = Message::ShareHeaders(response_headers);
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
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_getheaders() {
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
            .returning(move |_, _, _| Ok(response_headers.clone()));

        let _result = handle_getheaders(
            block_hashes,
            stop_block_hash,
            chain_store_handle,
            response_channel,
            swarm_tx,
        )
        .await;

        // Verify swarm message
        if let Some(SwarmSend::Response(channel, Message::ShareHeaders(headers))) =
            swarm_rx.recv().await
        {
            assert_eq!(channel, response_channel);
            assert_eq!(headers, vec![block1.header, block2.header]);
        } else {
            panic!("Expected SwarmSend::Response with ShareHeaders message");
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
            .expect_get_headers_for_locator()
            .returning(move |_, _, _| Ok(Vec::new()));

        // Drop the receiver to simulate send failure
        drop(swarm_rx);

        let result = handle_getheaders(
            block_hashes,
            stop_block_hash,
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
