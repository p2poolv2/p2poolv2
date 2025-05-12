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

use crate::stratum::messages::StratumMessage;
use tracing::debug;

#[allow(dead_code)]
// Handle incoming Stratum messages
// This function processes the incoming Stratum messages and returns a response
pub(crate) async fn handle_message(message: StratumMessage) -> Option<StratumMessage> {
    match message {
        StratumMessage::Request { id, method, params } => {
            debug!(
                "Handling request: id: {:?}, method: {:?}, params: {:?}",
                id, method, params
            );
            Some(StratumMessage::Response {
                id,
                result: Some(serde_json::json!("Success")),
                error: None,
            })
        }
        _ => None,
    }
}
