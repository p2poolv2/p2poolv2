// Copyright (C) 2024 [Kulpreet Singh]
//
//  This file is part of P2Poolv2
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
#[mockall_double::double]
use crate::shares::chain::actor::ChainHandle;
use std::error::Error;
use tokio::sync::mpsc;
use tracing::info;

/// Handle a GetHeaders request from a peer
/// - start from chain tip, find blockhashes up to the stop block hash
/// - limit the number of blocks to MAX_BLOCKS
/// - respond with send all headers found
pub async fn handle_getheaders<C: 'static>(
    block_hashes: Vec<bitcoin::BlockHash>,
    stop_block_hash: bitcoin::BlockHash,
    chain_handle: ChainHandle,
    response_channel: C,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error>> {
    info!("Received getheaders: {:?}", block_hashes);
    let response_headers = chain_handle
        .get_headers_for_locator(block_hashes, stop_block_hash)
        .await;
    let headers_message = Message::ShareHeaders(response_headers);
    swarm_tx
        .send(SwarmSend::Response(response_channel, headers_message))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::test_utils::TestBlockBuilder;

    use super::*;
    use bitcoin::BlockHash;
    use std::str::FromStr;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_getheaders() {
        let mut chain_handle = ChainHandle::default();
        let (swarm_tx, mut swarm_rx) = mpsc::channel::<SwarmSend<u32>>(1);
        let response_channel = 1u32;

        let block_hashes = vec![
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap(),
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap(),
        ];

        let block1 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000001")
            .build();

        let block2 = TestBlockBuilder::new()
            .blockhash("0000000000000000000000000000000000000000000000000000000000000002")
            .build();

        let response_headers = vec![block1.header.clone(), block2.header.clone()];

        let stop_block_hash =
            BlockHash::from_str("0000000000000000000000000000000000000000000000000000000000000002")
                .unwrap();

        // Set up mock expectations
        chain_handle
            .expect_get_headers_for_locator()
            .returning(move |_, _| response_headers.clone());

        let _result = handle_getheaders(
            block_hashes,
            stop_block_hash,
            chain_handle,
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
}
