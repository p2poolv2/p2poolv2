// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Configuration loading for the sim binary.
//!
//! Uses `#[serde(flatten)]` to deserialize both the regular node config and
//! the sim-specific `[sim]` section from a single TOML file.

use p2poolv2_config::{Config, SimConfig, validate_configuration_roots};
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
        validate_configuration_roots(path, &["sim"])?;
        config::Config::builder()
            .add_source(config::File::with_name(path))
            // Nesting uses `__` so that a single `_` stays part of a field name.
            // With a single-underscore separator, P2POOL_STORE_PPLNS_TTL_DAYS
            // addresses store.pplns.ttl.days, which does not exist, and the
            // override is silently discarded. See the env_override tests.
            .add_source(
                config::Environment::with_prefix("P2POOL")
                    .prefix_separator("_")
                    .separator("__"),
            )
            .build()?
            .try_deserialize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs, process};

    const SIM_SECTION: &str = r#"
[sim]
enabled = true
miner_address = "bcrt1qexample"
hashrate = 1000000.0
block_to_share_ratio = 1000
"#;

    #[test]
    fn sim_section_loads_with_flattened_node_config() {
        let contents = format!(
            "{}\n{SIM_SECTION}",
            include_str!("../../config.sample.toml")
        );
        let config_path =
            env::temp_dir().join(format!("p2poolv2-sim-config-{}.toml", process::id()));
        fs::write(&config_path, contents).unwrap();

        let result = SimNodeConfig::load(config_path.to_str().unwrap());
        fs::remove_file(config_path).unwrap();
        let config = result.unwrap();

        assert!(config.sim.enabled);
        assert_eq!(config.sim.hashrate, 1_000_000.0);
    }
}
