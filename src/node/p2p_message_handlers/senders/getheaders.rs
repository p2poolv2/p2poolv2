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
use crate::shares::ShareBlockHash;
use std::error::Error;
use tokio::sync::mpsc;

/// Handle outbound connection established events
/// Send a getheaders request to the peer
pub async fn send_getheaders<C: 'static>(
    peer_id: libp2p::PeerId,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend<C>>,
) -> Result<(), Box<dyn Error>> {
    let locator = chain_handle.build_locator().await;
    let stop_block_hash: ShareBlockHash =
        "0000000000000000000000000000000000000000000000000000000000000000".into();
    let getheaders_request = Message::GetShareHeaders(locator.clone(), stop_block_hash);
    swarm_tx
        .send(SwarmSend::Request(peer_id, getheaders_request))
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc::channel;

    #[tokio::test]
    async fn test_send_getheaders_success() {
        let (swarm_tx, mut swarm_rx) = channel::<SwarmSend<Message>>(1);
        let peer_id = libp2p::PeerId::random();
        let mut chain_handle = ChainHandle::default();

        let test_locator = vec![ShareBlockHash::from(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )];

        let test_locator_clone = test_locator.clone();

        chain_handle
            .expect_build_locator()
            .times(1)
            .return_once(move || test_locator_clone);

        let send_result = send_getheaders(peer_id, chain_handle, swarm_tx).await;
        assert!(send_result.is_ok());

        if let Some(SwarmSend::Request(received_peer_id, message)) = swarm_rx.recv().await {
            assert_eq!(received_peer_id, peer_id);
            match message {
                Message::GetShareHeaders(locator, stop_hash) => {
                    assert_eq!(locator, test_locator);
                    assert_eq!(
                        stop_hash,
                        ShareBlockHash::from(
                            "0000000000000000000000000000000000000000000000000000000000000000"
                        )
                    );
                }
                _ => panic!("Unexpected message type"),
            }
        } else {
            panic!("No message received");
        }
    }

    #[tokio::test]
    async fn test_send_getheaders_channel_closed() {
        let (swarm_tx, _) = channel::<SwarmSend<()>>(1);
        let peer_id = libp2p::PeerId::random();
        let mut chain_handle = ChainHandle::default();

        let test_locator = vec![ShareBlockHash::from(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )];

        chain_handle
            .expect_build_locator()
            .times(1)
            .return_once(move || test_locator.clone());

        let swarm_tx_clone = swarm_tx.clone();

        // Drop receiver to close channel
        drop(swarm_tx_clone);

        let send_result = send_getheaders(peer_id, chain_handle, swarm_tx).await;
        assert!(send_result.is_err());
    }
}
