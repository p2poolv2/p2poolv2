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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// Buffer size for channels to send messages to a client.
const MSG_CHANNEL_SIZE: usize = 10;

/// Represents client channel endpoints
pub struct ClientChannels {
    message_tx: mpsc::Sender<Arc<String>>,
    shutdown_tx: oneshot::Sender<()>,
}

/// Commands that can be sent to the ClientConnections actor
#[derive(Debug)]
pub enum ClientConnectionCommand {
    Add {
        addr: SocketAddr,
        response: oneshot::Sender<(mpsc::Receiver<Arc<String>>, oneshot::Receiver<()>)>,
    },
    SendToAll {
        message: Arc<String>,
    },
    SendToClient {
        addr: SocketAddr,
        message: Arc<String>,
    },
}

/// A handle to interact with the ClientConnections actor
#[derive(Clone)]
pub struct ClientConnectionsHandle {
    cmd_tx: mpsc::Sender<ClientConnectionCommand>,
}

impl ClientConnectionsHandle {
    /// Add a new client connection
    pub async fn add(
        &self,
        addr: SocketAddr,
    ) -> (mpsc::Receiver<Arc<String>>, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(ClientConnectionCommand::Add { addr, response: tx })
            .await;
        let (messages_rx, shutdown_rx) =
            rx.await.expect("ClientConnections actor has been dropped");
        (messages_rx, shutdown_rx)
    }

    /// Send a message to all clients
    /// Don't wait for the actor to respond. Fire and forget.
    pub async fn send_to_all(&self, message: Arc<String>) {
        let _ = self
            .cmd_tx
            .send(ClientConnectionCommand::SendToAll { message })
            .await;
    }

    /// Send a message to a specific client identified by its socket address.
    /// Don't wait for the actor to respond. Fire and forget.
    pub async fn send_to_client(&self, addr: SocketAddr, message: Arc<String>) -> bool {
        let cmd = ClientConnectionCommand::SendToClient { addr, message };
        self.cmd_tx.send(cmd).await.is_ok()
    }
}

#[cfg(test)]
mockall::mock! {
    pub ClientConnectionsHandle {
        pub async fn add(&self, addr: SocketAddr) -> (mpsc::Receiver<Arc<String>>, oneshot::Receiver<()>);
        pub async fn send_to_all(&self, message: Arc<String>);
        pub async fn send_to_client(&self, addr: SocketAddr, message: Arc<String>) -> bool;
    }
}

/// An actor model to manage connections to clients.
///
/// Most of the time we are not sending messages to clients, so we avoid using a Mutex to protect the `clients` map.
/// Instead, we use the actor model, where all add/remove/send operations are done from the same thread.
#[derive(Default)]
struct ClientConnections {
    clients: HashMap<SocketAddr, ClientChannels>,
}

impl ClientConnections {
    /// Adds a new client connection.
    ///
    /// Returns the receiver for the client connection and shutdown receiver.
    fn add(&mut self, addr: SocketAddr) -> (mpsc::Receiver<Arc<String>>, oneshot::Receiver<()>) {
        let (message_tx, message_rx) = mpsc::channel(MSG_CHANNEL_SIZE);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        self.clients.insert(
            addr,
            ClientChannels {
                message_tx,
                shutdown_tx,
            },
        );
        (message_rx, shutdown_rx)
    }

    /// Removes a client connection by its address.
    ///
    /// Returns true if the connection was found and removed, false otherwise.
    fn remove(&mut self, addr: &SocketAddr) -> bool {
        if let Some(channels) = self.clients.remove(addr) {
            // Try to send shutdown signal, but don't care if it fails
            let _ = channels.shutdown_tx.send(());
            true
        } else {
            false
        }
    }

    /// Sends a message to all connected clients.
    ///
    /// We use mpsc::channel#try_send for high latency sends. We don't flood the miners,
    /// so we know the failure should not come from a full channel.
    ///
    /// Clients that fail to receive the message are automatically removed which sends
    /// a shutdown signal to the connection.See remove.
    fn send_to_all(&mut self, message: Arc<String>) {
        // Collect addresses that failed to receive
        let mut failed_addrs = Vec::new();

        for (addr, channels) in &self.clients {
            if channels.message_tx.try_send(message.clone()).is_err() {
                failed_addrs.push(*addr);
            }
        }

        // Remove failed connections
        for addr in failed_addrs {
            self.remove(&addr);
        }
    }

    /// Sends a message to a specific client identified by its socket address.
    ///
    /// Returns true if the message was sent successfully, false if the client
    /// was not found or if sending failed (which also removes the client).
    fn send_to_client(&mut self, addr: &SocketAddr, message: Arc<String>) -> bool {
        if let Some(channels) = self.clients.get(addr) {
            if channels.message_tx.try_send(message).is_ok() {
                return true;
            }
            // If sending failed, remove the client
            self.remove(addr);
        }
        false
    }
}

/// Spawn a new ClientConnections actor and return a handle to it
pub async fn start_connections_handler() -> ClientConnectionsHandle {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<ClientConnectionCommand>(32);
    let handle = ClientConnectionsHandle { cmd_tx };

    let mut connections = ClientConnections::default();

    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                ClientConnectionCommand::Add { addr, response } => {
                    let (message_rx, shutdown_rx) = connections.add(addr);
                    let _ = response.send((message_rx, shutdown_rx));
                }
                ClientConnectionCommand::SendToAll { message } => {
                    connections.send_to_all(message);
                }
                ClientConnectionCommand::SendToClient { addr, message } => {
                    connections.send_to_client(&addr, message);
                }
            }
        }
    });
    handle
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    #[test]
    fn test_client_connections_add() {
        let mut connections = ClientConnections::default();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        assert_eq!(connections.clients.len(), 0);
        let (_message_rx, _shutdown_rx) = connections.add(addr);
        assert_eq!(connections.clients.len(), 1);
        assert!(connections.clients.contains_key(&addr));
    }

    #[test]
    fn test_client_connections_remove() {
        let mut connections = ClientConnections::default();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        // Add a client first
        connections.add(addr);
        assert_eq!(connections.clients.len(), 1);

        // Now remove it
        let removed = connections.remove(&addr);
        assert!(removed);
        assert_eq!(connections.clients.len(), 0);

        // Try to remove non-existent client
        let removed = connections.remove(&addr);
        assert!(!removed);
    }

    #[test]
    fn test_client_connections_send_to_all() {
        let mut connections = ClientConnections::default();
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);

        let (message_rx1, _) = connections.add(addr1);
        let (message_rx2, _) = connections.add(addr2);

        // Convert message_rx into a task that will receive messages
        let message = Arc::new("test message".to_string());
        connections.send_to_all(message.clone());

        // Verify the message was sent to both clients
        assert_eq!(connections.clients.len(), 2);

        // We can verify the channels received the messages
        let mut message_rx1 = message_rx1;
        let mut message_rx2 = message_rx2;

        // There should be one message in each channel
        assert_eq!(message_rx1.try_recv().unwrap(), message);
        assert_eq!(message_rx2.try_recv().unwrap(), message);

        // And no more messages
        assert!(message_rx1.try_recv().is_err());
        assert!(message_rx2.try_recv().is_err());
    }

    #[test]
    fn test_client_connections_send_to_client() {
        let mut connections = ClientConnections::default();
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);

        let (message_rx1, _) = connections.add(addr1);
        let (message_rx2, _) = connections.add(addr2);

        // Send message to specific client
        let message = Arc::new("client1 message".to_string());
        let success = connections.send_to_client(&addr1, message.clone());
        assert!(success);

        // Verify only the target client received the message
        let mut message_rx1 = message_rx1;
        let mut message_rx2 = message_rx2;

        assert_eq!(message_rx1.try_recv().unwrap(), message);
        assert!(message_rx2.try_recv().is_err());

        // Test sending to non-existent client
        let non_existent = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);
        let message = Arc::new("to nobody".to_string());
        let success = connections.send_to_client(&non_existent, message);
        assert!(!success);
    }

    #[tokio::test]
    async fn test_client_connections_handle() {
        // Spawn a new ClientConnections actor
        let handle = start_connections_handler().await;

        // Add two clients
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);

        let (mut message_rx1, _shutdown_rx1) = handle.add(addr1).await;
        let (mut message_rx2, _shutdown_rx2) = handle.add(addr2).await;

        // Send a message to all clients
        let message = Arc::new("test message".to_string());
        handle.send_to_all(message.clone()).await;

        // Verify that both clients received the message
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await; // Give time for message to be processed

        assert_eq!(message_rx1.try_recv().unwrap(), message);
        assert_eq!(message_rx2.try_recv().unwrap(), message);

        // Send another message to all clients
        let message2 = Arc::new("another message".to_string());
        handle.send_to_all(message2.clone()).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert_eq!(message_rx1.try_recv().unwrap(), message2);
        assert_eq!(message_rx2.try_recv().unwrap(), message2);
    }
}
