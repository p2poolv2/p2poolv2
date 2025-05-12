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

use serde::{Deserialize, Serialize};

// A generic stratum message structure
#[derive(Debug, Serialize, Deserialize)]
pub enum StratumMessage {
    Request {
        id: Option<u64>,
        method: Option<String>,
        params: Option<serde_json::Value>,
    },
    Response {
        id: Option<u64>,
        result: Option<serde_json::Value>,
        error: Option<serde_json::Value>,
    },
    Notification {
        method: String,
        params: serde_json::Value,
    },
}
