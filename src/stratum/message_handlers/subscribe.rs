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

use crate::stratum::messages::{Request, Response};
use crate::stratum::session::Session;
use serde_json::json;
use tracing::debug;

/// Handle the "mining.subscribe" message
/// This function is called when a miner subscribes to the Stratum server.
/// It sends a response with the subscription details.
/// The function accepts a mutable reference to a `Session` object, which informs the responses.
/// The session is also updated in response to received messages, if required.
pub async fn handle_subscribe<'a>(
    message: Request<'a>,
    session: &mut Session,
) -> Option<Response<'a>> {
    debug!("Handling mining.subscribe message");
    if session.subscribed {
        debug!("Client already subscribed. No response sent.");
        return None;
    }
    session.subscribed = true;
    Some(Response::new_ok(message.id, json!(true)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stratum::messages::Id;
    use crate::stratum::session::Session;

    #[tokio::test]
    async fn test_handle_subscribe_success() {
        // Setup
        let message = Request::new_subscribe(1, "UA".to_string(), "v1.0".to_string(), None);
        let mut session = Session::new(1);
        session.subscribed = false;

        // Execute
        let response = handle_subscribe(message, &mut session).await;

        // Verify
        assert!(response.is_some());
        let response = response.unwrap();
        assert_eq!(response.id, Some(Id::Number(1)));
        assert_eq!(response.result, Some(json!(true)));
        assert!(session.subscribed);
    }

    #[tokio::test]
    async fn test_handle_subscribe_already_subscribed() {
        // Setup
        let message = Request::new_subscribe(1, "UA".to_string(), "v1.0".to_string(), None);
        let mut session = Session::new(2);
        session.subscribed = true;

        // Execute
        let response = handle_subscribe(message, &mut session).await;

        // Verify
        assert!(response.is_none());
        assert!(session.subscribed);
    }
}
