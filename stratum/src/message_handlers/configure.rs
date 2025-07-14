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
use crate::messages::{Message, Request};
use crate::session::Session;
use tracing::debug;

/// Parse the parameters for the "mining.configure" message
/// This function checks if the parameters are valid for the "version-rolling" method.
/// It returns the parsed parameters if they are valid, or `None` if they are not
fn parse_configure_params(message: &Request) -> Option<serde_json::Value> {
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
                    if params.as_object()?.keys().next() == Some(&"version-rolling-mask".into()) {
                        Some(params)
                    } else {
                        debug!("Unexpected configuration parameter");
                        None
                    }
                } else {
                    debug!("Configuration parameters are not an object");
                    None
                }
            }
            None => {
                debug!("No configuration parameters provided");
                None
            }
        }
    } else {
        debug!("Unsupported configuration method: {}", message.params[0]);
        None
    }
}

/// Handle the "mining.configure" message
pub async fn handle_configure<'a, D: DifficultyAdjusterTrait>(
    message: Request<'a>,
    _session: &mut Session<D>,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.configure message");

    let params = parse_configure_params(&message);
    if let Some(_config_params) = params {
        Ok(vec![])
    } else {
        debug!("Invalid configuration parameters");
        Err(Error::InvalidParams)
    }
}
