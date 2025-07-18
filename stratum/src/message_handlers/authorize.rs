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

use crate::difficulty_adjuster::DifficultyAdjusterTrait;
use crate::error::Error;
use crate::messages::{Message, Response, SetDifficultyNotification, SimpleRequest};
use crate::session::Session;
use crate::work::notify::NotifyCmd;
use tracing::debug;

/// Handle the "mining.authorize" message
/// This function is called when a miner authorizes itself to the Stratum server.
/// It sends a response with the authorization status.
/// The function accepts a mutable reference to a `Session` object, which informs the responses.
/// The session is also updated in response to received messages, if required.
///
/// Some broken implementations of the Stratum protocol send the "mining.authorize" message before "mining.subscribe".
/// We supoprt this by not checking if the session is subscribed before authorizing.
///
/// TBH, this mining.authorize message is not needed at all. No server from ckpool to dataum to SRI is doing anything meaningful with it.
/// Stratum servers also allow all workers to authrorize over the same connection.
pub async fn handle_authorize<'a, D: DifficultyAdjusterTrait>(
    message: SimpleRequest<'a>,
    session: &mut Session<D>,
    addr: std::net::SocketAddr,
    notify_tx: tokio::sync::mpsc::Sender<NotifyCmd>,
    pool_min_difficulty: u64,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.authorize message");
    if session.username.is_some() {
        debug!("Client already authorized. No response sent.");
        return Err(Error::AuthorizationFailure(
            "Already authorized".to_string(),
        ));
    }
    session.username = Some(message.params[0].clone());
    session.password = Some(message.params[1].clone());
    let _ = notify_tx
        .send(NotifyCmd::SendToClient {
            client_address: addr,
        })
        .await;
    Ok(vec![
        Message::Response(Response::new_ok(message.id, serde_json::json!(true))),
        Message::SetDifficulty(SetDifficultyNotification::new(pool_min_difficulty)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::difficulty_adjuster::DifficultyAdjuster;
    use crate::messages::Id;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_handle_authorize_first_time() {
        // Setup
        let mut session = Session::<DifficultyAdjuster>::new(1, None, 1, 0x1fffe000);
        let request =
            SimpleRequest::new_authorize(12345, "worker1".to_string(), Some("x".to_string()));
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(1);

        // Execute
        let message = handle_authorize(
            request,
            &mut session,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            notify_tx,
            1000,
        )
        .await
        .unwrap();

        let (subscribe_response, difficulty_notification) = match &message[..] {
            [Message::Response(response), Message::SetDifficulty(difficulty_notification)] => {
                (response, difficulty_notification)
            }
            _ => panic!("Expected a Response message"),
        };

        // Verify
        assert_eq!(subscribe_response.id, Some(Id::Number(12345)));
        assert!(subscribe_response.error.is_none());
        assert!(subscribe_response.result.is_some());
        assert_eq!(
            subscribe_response.result.as_ref().unwrap(),
            &serde_json::Value::Bool(true)
        );
        assert_eq!(session.username, Some("worker1".to_string()));
        assert_eq!(session.password, Some("x".to_string()));

        let notify_cmd = notify_rx.try_recv();
        assert!(
            notify_cmd.is_ok(),
            "Notification should be sent to the client after authorization"
        );

        // Check difficulty notification
        assert_eq!(
            difficulty_notification.method, "mining.set_difficulty",
            "Expected method to be 'mining.set_difficulty'"
        );
        assert_eq!(
            difficulty_notification.params[0], 1000,
            "Expected difficulty notification to match pool minimum difficulty"
        );
    }

    #[tokio::test]
    async fn test_handle_authorize_already_authorized() {
        // Setup
        let mut session = Session::<DifficultyAdjuster>::new(1, None, 1, 0x1fffe000);
        session.username = Some("someusername".to_string());
        let request = SimpleRequest::new_authorize(
            12345,
            "worker1".to_string(),
            Some("password".to_string()),
        );
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(1);

        // Execute
        let message = handle_authorize(
            request,
            &mut session,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            notify_tx,
            1000,
        )
        .await;

        // Verify
        assert!(message.is_err());
        assert_eq!(session.username, Some("someusername".to_string()));
        assert!(session.password.is_none());

        let notify_cmd = notify_rx.try_recv();
        assert!(
            notify_cmd.is_err(),
            "No notification should be sent when already authorized"
        );
    }
}
