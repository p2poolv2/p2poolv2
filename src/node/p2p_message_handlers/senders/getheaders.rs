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
use libp2p::request_response::ResponseChannel;
use std::error::Error;
use tokio::sync::mpsc;

/// Handle outbound connection established events
/// Send a getheaders request to the peer
pub async fn send_getheaders(
    peer_id: libp2p::PeerId,
    chain_handle: ChainHandle,
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
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
