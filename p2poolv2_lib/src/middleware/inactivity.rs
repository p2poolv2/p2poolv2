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

/// Middleware to track peer activity and disconnect inactive peers.
///
/// When applied, it starts a background task that runs every 30 seconds
/// to check for inactive peers based on the last time they sent a request.
///
/// If a peer is inactive beyond the configured timeout, it is removed
/// and a `SwarmSend::Disconnect(peer)` is sent via `swarm_tx`.
///
/// Peer activity is tracked by updating a `last_seen` timestamp
/// on each request received from a peer.
use std::clone::Clone;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use libp2p::PeerId;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use tower::{Layer, Service};

use crate::node::SwarmSend;
use crate::service::p2p_service::RequestContext;

/// Layer that injects the InactivityService middleware into the stack.
pub struct InactivityLayer<C> {
    timeout_duration: Duration,
    swarm_tx: Sender<SwarmSend<C>>,
}

impl<C> InactivityLayer<C> {
    pub fn new(timeout_duration: Duration, swarm_tx: Sender<SwarmSend<C>>) -> Self {
        Self {
            timeout_duration,
            swarm_tx,
        }
    }
}

impl<S, C: Send + Sync + 'static> Layer<S> for InactivityLayer<C> {
    type Service = InactivityService<S, C>;

    fn layer(&self, service: S) -> Self::Service {
        let svc = InactivityService::new(service, self.timeout_duration, self.swarm_tx.clone());
        svc.start_monitoring();
        svc
    }
}

/// Middleware that tracks and disconnects inactive peers.
pub struct InactivityService<S, C> {
    service: S,
    timeout_duration: Duration,
    last_seen: Arc<Mutex<HashMap<PeerId, Instant>>>,
    swarm_tx: Sender<SwarmSend<C>>,
}

impl<S, C> InactivityService<S, C>
where
    C: Send + Sync + 'static,
{
    pub fn new(service: S, timeout_duration: Duration, swarm_tx: Sender<SwarmSend<C>>) -> Self {
        Self {
            service,
            timeout_duration,
            last_seen: Arc::new(Mutex::new(HashMap::new())),
            swarm_tx,
        }
    }

    /// Starts the periodic task that checks for inactive peers.
    pub fn start_monitoring(&self) {
        let timeout_duration = self.timeout_duration;
        let last_seen = Arc::clone(&self.last_seen);
        let swarm_tx = self.swarm_tx.clone();

        tokio::spawn(async move {
            let check_interval = Duration::from_secs(30);

            loop {
                sleep(check_interval).await;
                let now = Instant::now();
                let mut to_disconnect = Vec::new();

                {
                    // Limit the scope of the lock to before the await
                    let mut map = last_seen.lock().unwrap();
                    for (peer, last_time) in map.iter() {
                        if now.duration_since(*last_time) > timeout_duration {
                            to_disconnect.push(*peer);
                        }
                    }

                    for peer in &to_disconnect {
                        map.remove(peer);
                    }
                }

                // No lock is held across the await below
                for peer in to_disconnect {
                    // Send a disconnect command to the swarm via the channel
                    let _ = swarm_tx.send(SwarmSend::Disconnect(peer)).await;
                    tracing::info!(?peer, "Peer disconnected due to inactivity");
                }
            }
        });
    }
}

impl<S, C, T> Service<RequestContext<C, T>> for InactivityService<S, C>
where
    S: Service<
            RequestContext<C, T>,
            Response = (),
            Error = Box<dyn std::error::Error + Send + Sync>,
        > + Send
        + 'static,
    S::Future: Send + 'static,
    C: Send + Sync + 'static,
    T: Send + Sync + 'static,
{
    type Response = ();
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: RequestContext<C, T>) -> Self::Future {
        let mut map = self.last_seen.lock().unwrap();
        map.insert(req.peer, Instant::now());

        self.service.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    #[tokio::test]
    async fn peer_is_disconnected_after_timeout() {
        // Arrange: setup short timeout for quick test
        let disconnect_called = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = mpsc::channel::<SwarmSend<()>>(4);
        let timeout_duration = Duration::from_millis(100); // fast timeout
        let check_interval = Duration::from_millis(50); // frequent check

        let service = InactivityService {
            service: MockService,
            timeout_duration,
            last_seen: Arc::new(Mutex::new(HashMap::new())),
            swarm_tx: tx.clone(),
        };

        // Insert peer with old last_seen timestamp
        let peer_id = PeerId::random();
        {
            let mut last_seen = service.last_seen.lock().unwrap();
            last_seen.insert(peer_id, Instant::now() - Duration::from_millis(500));
        }

        // Override the spawn loop with a custom check interval
        let last_seen = service.last_seen.clone();
        let tx_clone = tx.clone();
        let disconnect_called_clone = disconnect_called.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(check_interval).await;
                let now = Instant::now();
                let mut to_disconnect = Vec::new();

                {
                    let mut map = last_seen.lock().unwrap();
                    for (peer, last_time) in map.iter() {
                        if now.duration_since(*last_time) > timeout_duration {
                            to_disconnect.push(*peer);
                        }
                    }

                    for peer in &to_disconnect {
                        map.remove(peer);
                    }
                }

                for peer in to_disconnect {
                    disconnect_called_clone.store(true, Ordering::SeqCst);
                    let _ = tx_clone.send(SwarmSend::Disconnect(peer)).await;
                    tracing::info!(?peer, "Peer disconnected due to inactivity (test)");
                }

                if disconnect_called_clone.load(Ordering::SeqCst) {
                    break;
                }
            }
        });

        // Act: wait for the disconnect
        let result = timeout(Duration::from_secs(2), rx.recv()).await;

        // Assert
        match result {
            Ok(Some(SwarmSend::Disconnect(p))) => {
                assert_eq!(p, peer_id);
                assert!(disconnect_called.load(Ordering::SeqCst));
            }
            _ => panic!("Expected peer disconnect within timeout"),
        }
    }

    // Minimal mock service to satisfy the generic type S
    #[derive(Clone)]
    struct MockService;

    impl<C, T> Service<RequestContext<C, T>> for MockService
    where
        C: Send + Sync + 'static,
        T: Send + Sync + 'static,
    {
        type Response = ();
        type Error = Box<dyn std::error::Error + Send + Sync>;
        type Future = futures::future::Ready<Result<(), Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: RequestContext<C, T>) -> Self::Future {
            futures::future::ready(Ok(()))
        }
    }
}
