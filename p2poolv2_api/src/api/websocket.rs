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

//! WebSocket handler for real-time monitoring event subscriptions.
//!
//! Clients connect to `/ws` and send subscribe/unsubscribe messages to
//! choose which event topics they receive. Authentication is validated
//! before the WebSocket upgrade via a `?token=` query parameter.

use crate::api::auth::validate_credentials;
use crate::api::server::AppState;
use axum::{
    extract::ws::{Message, WebSocket},
    extract::{Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::Response,
};
use p2poolv2_lib::monitoring_events::{MonitoringEvent, MonitoringEventSender};
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, warn};

/// Query parameters for the WebSocket endpoint.
#[derive(Deserialize)]
pub(crate) struct WsQuery {
    /// Base64-encoded `user:password` for authentication.
    token: Option<String>,
}

/// Topics a client can subscribe to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Topic {
    Shares,
    Peers,
}

const TOPIC_COUNT: usize = 2;

/// Client-to-server message format.
#[derive(Deserialize)]
struct ClientMessage {
    action: String,
    topic: String,
}

/// Parses a topic string into a `Topic` enum value.
fn parse_topic(topic: &str) -> Option<Topic> {
    match topic {
        "shares" => Some(Topic::Shares),
        "peers" => Some(Topic::Peers),
        _ => None,
    }
}

/// Returns true if the given event matches one of the subscribed topics.
fn event_matches_subscriptions(event: &MonitoringEvent, subscriptions: &HashSet<Topic>) -> bool {
    match event {
        MonitoringEvent::Share(_) => subscriptions.contains(&Topic::Shares),
        MonitoringEvent::Peer(_) => subscriptions.contains(&Topic::Peers),
    }
}

/// Axum handler for WebSocket upgrade requests.
///
/// Validates authentication (if configured) before upgrading. Returns
/// HTTP 401 if credentials are invalid or missing when auth is required.
pub(crate) async fn websocket_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<WsQuery>,
    upgrade: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    // Validate authentication before upgrade
    if let (Some(expected_user), Some(expected_token)) = (&state.auth_user, &state.auth_token) {
        let token = query.token.as_deref().unwrap_or("");
        validate_credentials(token, expected_user, expected_token)?;
    }

    let monitoring_event_sender = state.monitoring_event_sender.clone();
    Ok(upgrade.on_upgrade(move |socket| handle_socket(socket, monitoring_event_sender)))
}

/// Per-client WebSocket loop.
///
/// Subscribes to the broadcast channel and forwards matching events as
/// JSON text frames. Processes client subscribe/unsubscribe messages to
/// update the topic filter set.
async fn handle_socket(mut socket: WebSocket, monitoring_event_sender: MonitoringEventSender) {
    let mut event_receiver = monitoring_event_sender.subscribe();
    let mut subscriptions: HashSet<Topic> = HashSet::with_capacity(TOPIC_COUNT);

    loop {
        tokio::select! {
            client_message = socket.recv() => {
                match client_message {
                    Some(Ok(Message::Text(text))) => {
                        handle_client_message(&text, &mut subscriptions);
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        debug!("WebSocket client disconnected");
                        return;
                    }
                    Some(Err(error)) => {
                        debug!("WebSocket receive error: {error}");
                        return;
                    }
                    Some(Ok(_)) => {
                        // Ignore binary, ping, pong frames
                    }
                }
            }
            event_result = event_receiver.recv() => {
                match event_result {
                    Ok(event) => {
                        if event_matches_subscriptions(&event, &subscriptions) {
                            match serde_json::to_string(&event) {
                                Ok(json) => {
                                    if socket.send(Message::Text(json)).await.is_err() {
                                        debug!("WebSocket send failed, closing connection");
                                        return;
                                    }
                                }
                                Err(error) => {
                                    warn!("Failed to serialize monitoring event: {error}");
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
                        warn!("WebSocket client lagged, dropped {count} events");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        debug!("Monitoring event channel closed");
                        return;
                    }
                }
            }
        }
    }
}

/// Processes a client text message to update subscriptions.
fn handle_client_message(text: &str, subscriptions: &mut HashSet<Topic>) {
    let message: ClientMessage = match serde_json::from_str(text) {
        Ok(message) => message,
        Err(_) => {
            debug!("Invalid client message: {text}");
            return;
        }
    };

    let Some(topic) = parse_topic(&message.topic) else {
        debug!("Unknown topic: {}", message.topic);
        return;
    };

    match message.action.as_str() {
        "subscribe" => {
            subscriptions.insert(topic);
            debug!("Client subscribed to {:?}", topic);
        }
        "unsubscribe" => {
            subscriptions.remove(&topic);
            debug!("Client unsubscribed from {:?}", topic);
        }
        _ => {
            debug!("Unknown action: {}", message.action);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use p2poolv2_lib::monitoring_events::create_monitoring_event_channel;
    use p2poolv2_lib::store::dag_store::ShareInfo;

    #[test]
    fn test_parse_topic_valid() {
        assert_eq!(parse_topic("shares"), Some(Topic::Shares));
        assert_eq!(parse_topic("peers"), Some(Topic::Peers));
    }

    #[test]
    fn test_parse_topic_invalid() {
        assert_eq!(parse_topic("unknown"), None);
        assert_eq!(parse_topic(""), None);
    }

    #[test]
    fn test_event_matches_subscriptions() {
        let mut subscriptions = HashSet::with_capacity(TOPIC_COUNT);
        subscriptions.insert(Topic::Shares);

        let share_event = MonitoringEvent::Share(ShareInfo {
            blockhash: bitcoin::BlockHash::all_zeros(),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            height: 1,
            miner_address: "02aa".to_string(),
            timestamp: 0,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            uncles: vec![],
        });

        let peer_event = MonitoringEvent::Peer(p2poolv2_lib::monitoring_events::PeerResponse {
            peer_id: "peer1".to_string(),
            status: p2poolv2_lib::monitoring_events::PeerStatus::Connected,
            ..Default::default()
        });

        assert!(event_matches_subscriptions(&share_event, &subscriptions));
        assert!(!event_matches_subscriptions(&peer_event, &subscriptions));
    }

    #[test]
    fn test_handle_client_message_subscribe() {
        let mut subscriptions = HashSet::with_capacity(TOPIC_COUNT);
        handle_client_message(
            r#"{"action": "subscribe", "topic": "shares"}"#,
            &mut subscriptions,
        );
        assert!(subscriptions.contains(&Topic::Shares));
    }

    #[test]
    fn test_handle_client_message_unsubscribe() {
        let mut subscriptions = HashSet::with_capacity(TOPIC_COUNT);
        subscriptions.insert(Topic::Shares);
        handle_client_message(
            r#"{"action": "unsubscribe", "topic": "shares"}"#,
            &mut subscriptions,
        );
        assert!(!subscriptions.contains(&Topic::Shares));
    }

    #[test]
    fn test_handle_client_message_invalid_json() {
        let mut subscriptions = HashSet::with_capacity(TOPIC_COUNT);
        handle_client_message("not json", &mut subscriptions);
        assert!(subscriptions.is_empty());
    }

    #[test]
    fn test_handle_client_message_unknown_topic() {
        let mut subscriptions = HashSet::with_capacity(TOPIC_COUNT);
        handle_client_message(
            r#"{"action": "subscribe", "topic": "unknown"}"#,
            &mut subscriptions,
        );
        assert!(subscriptions.is_empty());
    }

    #[test]
    fn test_handle_client_message_unknown_action() {
        let mut subscriptions = HashSet::with_capacity(TOPIC_COUNT);
        handle_client_message(
            r#"{"action": "toggle", "topic": "shares"}"#,
            &mut subscriptions,
        );
        assert!(subscriptions.is_empty());
    }

    #[tokio::test]
    async fn test_broadcast_event_delivered_to_subscriber() {
        let (sender, _guard) = create_monitoring_event_channel();
        let mut receiver = sender.subscribe();

        // Build subscription set as handle_socket would
        let mut subscriptions = HashSet::with_capacity(TOPIC_COUNT);
        handle_client_message(
            r#"{"action": "subscribe", "topic": "shares"}"#,
            &mut subscriptions,
        );

        let share_event = MonitoringEvent::Share(ShareInfo {
            blockhash: bitcoin::BlockHash::all_zeros(),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            height: 42,
            miner_address: "02aa".to_string(),
            timestamp: 1000,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            uncles: vec![],
        });

        sender.send(share_event).unwrap();

        let received = receiver.recv().await.unwrap();
        assert!(event_matches_subscriptions(&received, &subscriptions));

        let json = serde_json::to_string(&received).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["topic"], "Share");
        assert_eq!(parsed["data"]["height"], 42);
        assert_eq!(parsed["data"]["miner_address"], "02aa");
    }

    #[tokio::test]
    async fn test_broadcast_event_filtered_for_unsubscribed_topic() {
        let (sender, _guard) = create_monitoring_event_channel();
        let mut receiver = sender.subscribe();

        // Subscribe to peers only
        let mut subscriptions = HashSet::with_capacity(TOPIC_COUNT);
        handle_client_message(
            r#"{"action": "subscribe", "topic": "peers"}"#,
            &mut subscriptions,
        );

        let share_event = MonitoringEvent::Share(ShareInfo {
            blockhash: bitcoin::BlockHash::all_zeros(),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            height: 1,
            miner_address: "02bb".to_string(),
            timestamp: 0,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            uncles: vec![],
        });

        sender.send(share_event).unwrap();

        let received = receiver.recv().await.unwrap();
        // Share event should NOT match a peers-only subscription
        assert!(!event_matches_subscriptions(&received, &subscriptions));
    }
}
