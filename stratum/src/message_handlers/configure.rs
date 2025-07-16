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
use crate::messages::{Message, Request, Response};
use crate::session::Session;
use tracing::debug;

/// Parse the parameters for the "mining.configure" message
/// This function checks if the parameters are valid for the "version-rolling" method.
fn parse_configure_params(
    message: &Request,
) -> Result<serde_json::Map<String, serde_json::Value>, Error> {
    if message.params[0] == "version-rolling" {
        let config_params = match serde_json::from_str::<serde_json::Value>(&message.params[1]) {
            Ok(value) => Some(value),
            Err(_) => {
                debug!("Failed to parse configuration parameters");
                None
            }
        };

        match config_params {
            Some(params) => {
                if params.is_object() {
                    debug!("Parsed configuration parameters: {:?}", params);
                    Ok(params.as_object().unwrap().clone())
                } else {
                    Err(Error::InvalidParams(
                        "Configuration parameters are not an object".into(),
                    ))
                }
            }
            None => Err(Error::InvalidParams(
                "No configuration parameters provided".into(),
            )),
        }
    } else {
        // return empty map for unsupported methods with Ok.
        Ok(serde_json::Map::new())
    }
}

/// Handle the "mining.configure" message
pub async fn handle_configure<'a, D: DifficultyAdjusterTrait>(
    message: Request<'a>,
    version_mask: u32,
    _session: &mut Session<D>,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.configure message");

    let params = parse_configure_params(&message);
    if let Ok(config_params) = params {
        if config_params.contains_key("version-rolling.mask") {
            Ok(vec![Message::Response(Response::new_ok(
                message.id,
                serde_json::json!({
                    "version-rolling": true,
                    "version-rolling.mask": format!("{:x}", version_mask)}),
            ))])
        } else {
            // return Ok, so we don't disconnect client. Also, we don't send any message back for unsupported configure methods.
            Ok(vec![])
        }
    } else {
        debug!("Invalid configuration parameters");
        Err(Error::InvalidParams(
            "Invalid configuration parameters".into(),
        ))
    }
}

#[cfg(test)]
mod mining_configure_parse_tests {
    use super::*;
    use crate::messages::{Id, Message, Request};
    use crate::session::Session;
    use std::borrow::Cow;

    #[test]
    fn test_parse_configure_params_valid() {
        let message = Request {
            id: Some(Id::Number(1)),
            method: Cow::Owned("mining.configure".to_string()),
            params: Cow::Owned(vec![
                "version-rolling".to_string(),
                r#"{"version-rolling.mask":"ffffffff"}"#.to_string(),
            ]),
        };
        let result = parse_configure_params(&message);
        assert!(result.is_ok());
        let params = result.unwrap();
        assert!(params.contains_key("version-rolling.mask"));
        assert_eq!(params["version-rolling.mask"], "ffffffff");
    }

    #[test]
    fn test_parse_configure_params_invalid_mask_should_return_ok() {
        let message = Request {
            id: Some(Id::Number(1)),
            method: Cow::Owned("mining.configure".to_string()),
            params: Cow::Owned(vec![
                "version-rolling".to_string(),
                r#"{"version-rolling.mask":"invalid"}"#.to_string(),
            ]),
        };
        let result = parse_configure_params(&message);
        assert!(result.is_ok());
        let params = result.unwrap();
        assert!(params.contains_key("version-rolling.mask"));
        assert_eq!(params["version-rolling.mask"], "invalid");
    }

    #[test]
    fn test_parse_configure_params_unsupported_method_should_return_ok() {
        let message = Request {
            id: Some(Id::Number(1)),
            method: Cow::Owned("mining.configure".to_string()),
            params: Cow::Owned(vec!["unsupported-method".to_string(), r#"{}"#.to_string()]),
        };

        let result = parse_configure_params(&message);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_configure_params_not_object_should_return_err() {
        let message = Request {
            id: Some(Id::Number(1)),
            method: Cow::Owned("mining.configure".to_string()),
            params: Cow::Owned(vec![
                "version-rolling".to_string(),
                r#"["not", "an", "object"]"#.to_string(),
            ]),
        };

        let result = parse_configure_params(&message);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_configure_params_missing_required_key_should_return_ok() {
        let message = Request {
            id: Some(Id::Number(1)),
            method: Cow::Owned("mining.configure".to_string()),
            params: Cow::Owned(vec![
                "version-rolling".to_string(),
                r#"{"wrong-key":"value"}"#.to_string(),
            ]),
        };

        let result = parse_configure_params(&message);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_configure_params_additional_keys_should_return_ok() {
        let message = Request {
            id: Some(Id::Number(1)),
            method: Cow::Owned("mining.configure".to_string()),
            params: Cow::Owned(vec![
                "version-rolling".to_string(),
                r#"{"version-rolling.mask":"ffffffff", "extra-param":"value"}"#.to_string(),
            ]),
        };

        let result = parse_configure_params(&message);
        assert!(result.is_ok());
        let params = result.unwrap();
        assert!(params.contains_key("version-rolling.mask"));
        assert_eq!(params["version-rolling.mask"], "ffffffff");
        assert_eq!(params["extra-param"], "value");
    }
}

#[cfg(test)]
mod mining_configure_response_tests {
    use super::*;
    use crate::{
        difficulty_adjuster::DifficultyAdjuster,
        messages::{Id, Message, Request},
    };
    use std::borrow::Cow;

    #[tokio::test]
    async fn test_handle_configure_valid_request() {
        let message = Request {
            id: Some(Id::Number(1)),
            method: Cow::Owned("mining.configure".to_string()),
            params: Cow::Owned(vec![
                "version-rolling".to_string(),
                r#"{"version-rolling.mask":"ffffffff"}"#.to_string(),
            ]),
        };

        let mut session = Session::<DifficultyAdjuster>::new(1, Some(1000), 100000);
        let version_mask = 0x1fffe000;

        let result = handle_configure(message, version_mask, &mut session).await;
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
