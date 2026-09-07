// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use bitcoindrpc::BitcoinRpcConfig;
use p2poolv2_lib::config::{
    ApiConfig, Config, LoggingConfig, NetworkConfig, StoreConfig, StratumConfig,
};

/// Build a default test configuration with test values that can be replaced later by each test
/// We avoid providing a Default implementation for Config as it exposes us to the risk of
/// accidentally using the default values in production.
/// WARNING: This is a test fixture and should not be used anywhere else.
pub fn default_test_config() -> Config {
    Config {
        network: NetworkConfig {
            listen_address: "/ip4/127.0.0.1/tcp/6891".to_string(),
            dial_peers: vec![],
            max_pending_incoming: 10,
            max_pending_outgoing: 10,
            max_established_incoming: 50,
            max_established_outgoing: 50,
            max_established_per_peer: 3,
            max_workbase_per_second: 10,
            max_userworkbase_per_second: 10,
            max_miningshare_per_second: 100,
            max_inventory_per_second: 100,
            max_transaction_per_second: 100,
            max_requests_per_second: 1,
            dial_timeout_secs: 30,
            blocked_ips: vec![],
            external_address: None,
        },
        bitcoinrpc: BitcoinRpcConfig {
            url: "http://localhost:8332".to_string(),
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        },
        store: StoreConfig {
            path: "test_chain.db".to_string(),
            background_task_frequency_hours: 1,
            pplns_ttl_days: 3,
        },
        stratum: StratumConfig::new_for_test_default(),
        logging: LoggingConfig {
            console: Some(true),
            level: "info".to_string(),
            file: Some("./p2pool.log".to_string()),
            stats_dir: "./logs/stats".to_string(),
        },
        api: ApiConfig {
            hostname: "127.0.0.1".to_string(),
            port: 3000,
            auth_user: None,
            auth_token: None,
            auth_password: None,
            cors_allowed: false,
        },
    }
}
