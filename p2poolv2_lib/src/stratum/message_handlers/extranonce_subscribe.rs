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

use crate::stratum::error::Error;
use crate::stratum::messages::{Message, Response, SimpleRequest};
use serde_json::json;
use tracing::debug;

/// Handle the "mining.extranonce.subscribe" message (xnsub).
///
/// Miners send this to indicate they support mid-session extranonce
/// changes via `mining.set_extranonce`. P2Poolv2 assigns a fixed
/// extranonce1 per session and never changes it, so we acknowledge
/// the subscription but never send extranonce updates.
pub async fn handle_extranonce_subscribe<'a>(
    message: SimpleRequest<'a>,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Acknowledging mining.extranonce.subscribe (no-op)");
    Ok(vec![Message::Response(Response::new_ok(
        message.id,
        json!(true),
    ))])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stratum::messages::Id;
    use std::borrow::Cow;

    #[tokio::test]
    async fn test_extranonce_subscribe_returns_true() {
        let message = SimpleRequest {
            id: Some(Id::Number(3)),
            method: Cow::Borrowed("mining.extranonce.subscribe"),
            params: Cow::Owned(vec![]),
        };

        let result = handle_extranonce_subscribe(message).await;
        assert!(result.is_ok());
        let messages = result.unwrap();
        assert_eq!(messages.len(), 1);

        let response = match &messages[0] {
            Message::Response(response) => response,
            _ => panic!("Expected a Response message"),
        };
        assert_eq!(response.id, Some(Id::Number(3)));
        assert_eq!(response.result, Some(json!(true)));
        assert!(response.error.is_none());
    }
}
