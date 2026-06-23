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

//! Configuration loading for the sim binary.
//!
//! Uses `#[serde(flatten)]` to deserialize both the regular node config and
//! the sim-specific `[sim]` section from a single TOML file.

use p2poolv2_config::{Config, SimConfig};
use serde::Deserialize;

/// Combined config that loads the regular node config plus the `[sim]` section.
#[derive(Debug, Deserialize, Clone)]
pub struct SimNodeConfig {
    #[serde(flatten)]
    pub node: Config,
    pub sim: SimConfig,
}

impl SimNodeConfig {
    /// Load from a TOML config file path.
    pub fn load(path: &str) -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .add_source(config::File::with_name(path))
            .add_source(config::Environment::with_prefix("P2POOL").separator("_"))
            .build()?
            .try_deserialize()
    }
}
