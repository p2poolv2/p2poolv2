// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use std::time::{Duration, Instant};
// use crate::config::StratumConfig;
use crate::config::Config;
use crate::stratum::error::Error;
use crate::stratum::session::Session;
use crate::stratum::difficulty_adjuster::DifficultyAdjuster;

use tracing::error;


#[derive(Clone, Copy)]
pub struct SessionTimeouts {
    pub first_share_timeout: Duration,
    pub inactivity_timeout: Duration,
    pub monitor_interval: Duration,
}

impl SessionTimeouts {
    pub fn new() -> Self {
        let config_path = "../config.toml";
        let stratum_config = match Config::load(config_path) {
            Ok(config) => config.stratum,
            Err(e) => {
                error!("Failed to load config: {e}");
                return Self::default();
            }
        };
        Self {
            first_share_timeout: Duration::from_secs(stratum_config.first_share_timeout),
            inactivity_timeout: Duration::from_secs(stratum_config.inactivity_timeout),
            monitor_interval: Duration::from_secs(stratum_config.monitor_interval),
        }
    }
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            first_share_timeout: Duration::from_secs(900),
            inactivity_timeout: Duration::from_secs(900),
            monitor_interval: Duration::from_secs(10),
        }
    }
}


/// Checks for session timeouts based on initialization and inactivity periods
/// 
/// This function evaluates the session's state to determine if it has exceeded
/// the allowed time for completing the initialization (if not yet subscribed or
/// authorized) or for remaining inactive after submitting a share
pub fn check_session_timeouts(
    session: &Session<DifficultyAdjuster>,
    timeouts: &SessionTimeouts,
) -> Result<(), Error> {
    let now = Instant::now();
    if !(session.subscribed && session.username.is_some()) {
        let since_connect = now.duration_since(session.connected_at);

        if since_connect >= timeouts.first_share_timeout {
            error!("Initialization timeout");
            return Err(Error::TimeoutError);
        }
    }

    let last_share_time = match session.last_share_time {
        Some(val) => val,
        None => {
            error!("Error retrieving the time of the last share sent");
            return Err(Error::TimeoutError)
        },
    };
    let since_last_share = now.duration_since(last_share_time);
    if session.username.is_some()
        && session.last_share_time.is_some()
        && since_last_share >= timeouts.inactivity_timeout
    {
        error!("Inactivity timeout");
        return Err(Error::TimeoutError);
    }

    Ok(())
}


#[cfg(test)]
mod timeout_tests {
        #[tokio::test]
    async fn test_first_share_timeout() {
        tokio::time::pause();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let mut writer = Vec::new();
        let (_, message_rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let (shares_tx, _shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            metrics: metrics_handle,
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            shares_tx,
            network: bitcoin::network::Network::Regtest,
            store,
        };

        let reader = BufReader::new(io::empty());

        let handle = tokio::spawn(async move {
            let result = handle_connection(
                reader,
                &mut writer,
                addr,
                message_rx,
                shutdown_rx,
                0x1fffe000,
                ctx,
            )
            .await;
            result
        });

        tokio::time::advance(Duration::from_secs(2)).await;

        // The task should have completed (disconnected)
        let result = handle.await.unwrap();
        assert!(result.is_ok()); // Connection closed due to timeout
    }

    #[tokio::test]
    async fn test_inactivity_timeout() {
        tokio::time::pause();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let mut writer = Vec::new();
        let (mut message_tx, message_rx) = mpsc::channel(10);
        let (_shutdown_tx, shutdown_rx) = oneshot::channel();
        let (notify_tx, _notify_rx) = mpsc::channel(10);
        let tracker_handle = start_tracker_actor();
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let (shares_tx, _shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            metrics: metrics_handle,
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            shares_tx,
            network: bitcoin::network::Network::Regtest,
            store,
        };

        let subscribe = serde_json::to_string(&SimpleRequest::new_subscribe(
            1,
            "agent".to_string(),
            "1.0".to_string(),
            None,
        ))
        .unwrap();
        let authorize = serde_json::to_string(&SimpleRequest::new_authorize(
            2,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            None,
        ))
        .unwrap();
        let submit = serde_json::to_string(&SimpleRequest::new_submit(
            3,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            "1".to_string(),
            "00000001".to_string(),
            "00000001".to_string(),
            "00000001".to_string(),
        ))
        .unwrap();

        let input = format!("{subscribe}\n{authorize}\n{submit}\n");
        let reader = BufReader::new(input.as_bytes());

        let handle = tokio::spawn(async move {
            let result = handle_connection(
                reader,
                &mut writer,
                addr,
                message_rx,
                shutdown_rx,
                0x1fffe000,
                ctx,
            )
            .await;
            result
        });

        tokio::time::advance(Duration::from_secs(1)).await;

        message_tx
            .send(Arc::new("dummy notify".to_string()))
            .await
            .unwrap();

        tokio::time::advance(Duration::from_secs(900)).await;

        let result = handle.await.unwrap();
        assert!(result.is_ok());
    }
}