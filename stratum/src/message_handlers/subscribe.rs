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
use crate::session::{Session, EXTRANONCE2_SIZE};
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
) -> Result<Response<'a>, Error> {
    debug!("Handling mining.subscribe message");
    if session.subscribed {
        debug!("Client already subscribed. No response sent.");
        return Err(Error::SubscriptionFailure("Already subscribed".to_string()));
    }
    session.subscribed = true;
    Ok(Response::new_ok(
        message.id,
        json!([
            [
                ["mining.notify", format!("{}1", session.id)], // we expect different ids in notify and set_difficulty, thus we suffix with 1 and 2
                ["mining.set_difficulty", format!("{}2", session.id)],
            ],
            session.enonce1_hex,
            EXTRANONCE2_SIZE,
        ]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Id;
    use crate::session::Session;

    #[tokio::test]
    async fn test_handle_subscribe_success() {
        // Setup
        let message = Request::new_subscribe(1, "UA".to_string(), "v1.0".to_string(), None);
        let mut session = Session::new(1);
        session.subscribed = false;

        // Execute
        let response = handle_subscribe(message, &mut session).await;

        // Verify
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.id, Some(Id::Number(1)));
        // Check the response.result is Some and is an array as expected
        let result = response
            .result
            .as_ref()
            .expect("Expected result in response");
        let arr = result.as_array().expect("Expected result to be an array");
        assert_eq!(arr.len(), 3);

        // 1. Check subscriptions array
        let subscriptions = arr[0]
            .as_array()
            .expect("Expected subscriptions to be an array");
        assert_eq!(subscriptions.len(), 2);

        let notify = subscriptions[0]
            .as_array()
            .expect("Expected mining.notify to be an array");
        assert_eq!(notify[0], "mining.notify");
        assert_eq!(notify[1], format!("{}1", session.id));

        let set_difficulty = subscriptions[1]
            .as_array()
            .expect("Expected mining.set_difficulty to be an array");
        assert_eq!(set_difficulty[0], "mining.set_difficulty");
        assert_eq!(set_difficulty[1], format!("{}2", session.id));

        // 2. Check enonce1
        assert_eq!(arr[1], session.enonce1_hex);

        // 3. Check extranonce2_size
        assert_eq!(arr[2], serde_json::json!(EXTRANONCE2_SIZE));
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
        assert!(response.is_err());
        assert!(session.subscribed);
    }
}
