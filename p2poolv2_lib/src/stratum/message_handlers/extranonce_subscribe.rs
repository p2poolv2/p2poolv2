// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
