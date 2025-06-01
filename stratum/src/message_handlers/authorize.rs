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

use crate::error::Error;
use crate::messages::{Request, Response};
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
pub async fn handle_authorize<'a>(
    message: Request<'a>,
    session: &mut Session,
    addr: std::net::SocketAddr,
    notify_tx: tokio::sync::mpsc::Sender<NotifyCmd>,
) -> Result<Response<'a>, Error> {
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
    Ok(Response::new_ok(message.id, serde_json::json!(true)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Id;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_handle_authorize_first_time() {
        // Setup
        let mut session = Session::new(1);
        let request = Request::new_authorize(12345, "worker1".to_string(), Some("x".to_string()));
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(1);

        // Execute
        let response = handle_authorize(
            request,
            &mut session,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            notify_tx,
        )
        .await;

        // Verify
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.id, Some(Id::Number(12345)));
        assert!(response.error.is_none());
        assert!(response.result.is_some());
        assert_eq!(response.result.unwrap(), true);
        assert_eq!(session.username, Some("worker1".to_string()));
        assert_eq!(session.password, Some("x".to_string()));

        let notify_cmd = notify_rx.try_recv();
        assert!(
            notify_cmd.is_ok(),
            "Notification should be sent to the client after authorization"
        );
    }

    #[tokio::test]
    async fn test_handle_authorize_already_authorized() {
        // Setup
        let mut session = Session::new(1);
        session.username = Some("someusername".to_string());
        let request =
            Request::new_authorize(12345, "worker1".to_string(), Some("password".to_string()));
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(1);

        // Execute
        let response = handle_authorize(
            request,
            &mut session,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            notify_tx,
        )
        .await;

        // Verify
        assert!(response.is_err());
        assert_eq!(session.username, Some("someusername".to_string()));
        assert!(session.password.is_none());

        let notify_cmd = notify_rx.try_recv();
        assert!(
            notify_cmd.is_err(),
            "No notification should be sent when already authorized"
        );
    }
}
