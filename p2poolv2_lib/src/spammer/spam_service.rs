// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use std::error::Error;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tower::Service;

use crate::node::messages::Message;
use crate::node::SwarmSend;
use libp2p::request_response::ResponseChannel;
use libp2p::PeerId;

/// A background service that continuously sends spam messages
/// to a list of target peers using the libp2p swarm channel.
#[derive(Clone)]
pub struct SpammerService {
    swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
    peers: Vec<PeerId>,
    message: Message,
}

/// Creates a new SpammerService and starts the spam loop in the background.
///
/// # Arguments
/// * `swarm_tx` - Channel to send swarm messages.
/// * `peers` - List of peer IDs to spam.
/// * `message` - The message to repeatedly send.
/// * `interval` - How frequently to send the spam message.
///
/// # Returns
/// - the service instance (for optional use)
/// - the background task handle (which can be awaited or ignored)
impl SpammerService {
    pub fn new(
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
        peers: Vec<PeerId>,
        message: Message,
        interval: Duration,
    ) -> (Self, JoinHandle<()>) {
        let spammer = Self {
            swarm_tx: swarm_tx.clone(),
            peers,
            message,
        };

        let handle = tokio::spawn(Self::spam_loop(
            swarm_tx,
            spammer.peers.clone(),
            spammer.message.clone(),
            interval,
        ));
        (spammer, handle)
    }

    async fn spam_loop(
        swarm_tx: mpsc::Sender<SwarmSend<ResponseChannel<Message>>>,
        peers: Vec<PeerId>,
        message: Message,
        interval: Duration,
    ) {
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            for peer in &peers {
                let peer_id = *peer;
                let send = SwarmSend::Request(peer_id, message.clone());

                let tx = swarm_tx.clone();
                tokio::spawn(async move {
                    if let Err(err) = tx.send(send).await {
                        tracing::warn!("Failed to send spam to {}: {}", peer_id, err);
                    }
                });
            }
        }
    }
}

impl Service<()> for SpammerService {
    type Response = ();
    type Error = Box<dyn Error + Send + Sync>;
    type Future = futures::future::Ready<Result<(), Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        futures::future::ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::messages::Message;
    use libp2p::PeerId;
    use std::str::FromStr;
    use tokio::sync::mpsc;

    fn mock_peer_id() -> PeerId {
        PeerId::from_str("12D3KooWJ4HSxGULsKfKwXe3G74rXK3ZEFc9tznJfQPtSJEyCMqG").unwrap()
    }

    #[tokio::test]
    async fn test_spammer_sends_to_all_peers() {
        let (tx, mut rx) = mpsc::channel::<SwarmSend<ResponseChannel<Message>>>(10);
        let peers = vec![mock_peer_id(), mock_peer_id()];
        let message = Message::NotFound(());

        let (_spammer, _handle) = SpammerService::new(
            tx.clone(),
            peers.clone(),
            message.clone(),
            Duration::from_millis(50),
        );

        let mut received = 0;
        let timeout = tokio::time::timeout(Duration::from_millis(500), async {
            while let Some(SwarmSend::Request(peer_id, msg)) = rx.recv().await {
                assert!(peers.contains(&peer_id));
                received += 1;
                if received >= peers.len() {
                    break;
                }
            }
        });

        assert!(
            timeout.await.is_ok(),
            "Spammer did not send expected messages in time"
        );
        assert_eq!(
            received,
            peers.len(),
            "Did not receive messages for all peers"
        );
    }

    #[tokio::test]
    async fn test_spammer_handles_empty_peers_list() {
        let (tx, mut rx) = mpsc::channel::<SwarmSend<ResponseChannel<Message>>>(10);
        let peers = vec![];
        let message = Message::NotFound(());

        let (_spammer, _handle) =
            SpammerService::new(tx, peers, message, Duration::from_millis(10));

        // Wait to confirm nothing is sent
        let result = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;

        assert!(result.is_err(), "Spammer sent a message even with no peers");
    }
}
