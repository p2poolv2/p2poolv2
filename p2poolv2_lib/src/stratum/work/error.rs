// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde::{Deserialize, Serialize};
use std::error::Error;

/// Error handling when dealing with work and coinbase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkError {
    pub message: String,
}

impl Error for WorkError {}
impl std::fmt::Display for WorkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<p2poolv2_config::ConfigError> for WorkError {
    fn from(error: p2poolv2_config::ConfigError) -> Self {
        WorkError {
            message: error.to_string(),
        }
    }
}
