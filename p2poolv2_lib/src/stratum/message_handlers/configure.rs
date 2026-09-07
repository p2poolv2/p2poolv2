// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::stratum::difficulty_adjuster::DifficultyAdjusterTrait;
use crate::stratum::error::Error;
use crate::stratum::messages::{Message, MiningConfigure, Request, Response};
use crate::stratum::session::Session;
use tracing::debug;

/// Handle the "mining.configure" message
pub async fn handle_configure<'a, D: DifficultyAdjusterTrait>(
    request: Request<'a>,
    session: &Session<D>,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.configure message");
    match request {
        Request::MiningConfigureRequest(configure) => {
            debug!("Received mining.configure request: {:?}", configure);
            handle_mining_configure(configure, session)
        }
        _ => Err(Error::InvalidParams(
            "Invalid method for mining.configure".into(),
        )),
    }
}

fn handle_mining_configure<'a>(
    request: MiningConfigure,
    session: &Session<impl DifficultyAdjusterTrait>,
) -> Result<Vec<Message<'a>>, Error> {
    let configure_params = &request.params.1;
    if configure_params.version_rolling_mask.is_some() {
        Ok(vec![Message::Response(Response::new_ok(
            Some(request.id),
            serde_json::json!({
                    "version-rolling": true,
                    "version-rolling.mask": format!("{:x}", session.version_mask)}),
        ))])
    } else {
        // return Ok, so we don't disconnect client. Also, we don't send any message back for unsupported configure methods.
        Ok(vec![])
    }
}

#[cfg(test)]
mod mining_configure_response_tests {
    use super::*;
    use crate::{
        stratum::difficulty_adjuster::DifficultyAdjuster,
        stratum::messages::{Id, Message, MiningConfigure},
    };

    #[tokio::test]
    async fn test_handle_configure_valid_request() {
        let message = MiningConfigure::new_version_rolling_configure(
            1,
            Some("ffffffff".to_string()),
            None,
            None,
        );

        let session = Session::<DifficultyAdjuster>::new(1, 1, Some(1000), 0x1fffe000);

        let result = handle_configure(message, &session).await;
        assert!(result.is_ok());
        let messages = result.unwrap();
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            Message::Response(response) => {
                assert_eq!(response.id, Some(Id::Number(1)));
                assert!(response.error.is_none());
                assert!(response.result.is_some());
                let result = response.result.as_ref().unwrap();
                assert_eq!(
                    result,
                    &serde_json::json!({
                        "version-rolling": true,
                        "version-rolling.mask": "1fffe000"
                    })
                );
            }
            _ => panic!("Expected a Response message"),
        }
    }
}
