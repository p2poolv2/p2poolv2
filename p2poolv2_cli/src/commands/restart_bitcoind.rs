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

use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient};
use p2poolv2_lib::config::BitcoindConfig;
use std::error::Error;
use std::time::Duration;
use tracing::{error, info, warn};

/// Maximum number of seconds to wait for bitcoind to stop
const STOP_TIMEOUT_SECS: u64 = 60;

/// Maximum number of seconds to wait for bitcoind to become healthy after restart
const START_TIMEOUT_SECS: u64 = 60;

/// Interval between health-check polls
const POLL_INTERVAL_SECS: u64 = 1;

/// Execute the restart-bitcoind command.
///
/// This function:
/// 1. Sends a `stop` RPC call to gracefully shut down bitcoind
/// 2. Polls until bitcoind is no longer responsive (connection refused)
/// 3. If `stop_only` is false and `restart_cmd` is configured, spawns a new
///    bitcoind process and waits for it to become healthy
///
/// # Arguments
/// * `rpc_config` - Bitcoin RPC connection configuration
/// * `bitcoind_config` - Optional bitcoind process management configuration
/// * `stop_only` - If true, only stop bitcoind without attempting restart
pub async fn execute(
    rpc_config: &BitcoinRpcConfig,
    bitcoind_config: Option<&BitcoindConfig>,
    stop_only: bool,
) -> Result<(), Box<dyn Error>> {
    let client =
        BitcoindRpcClient::new(&rpc_config.url, &rpc_config.username, &rpc_config.password)?;


    info!("Sending stop RPC to bitcoind at {}...", rpc_config.url);
    match client.stop().await {
        Ok(msg) => {
            info!("bitcoind responded: {}", msg);
        }
        Err(e) => {
            // Connection refused likely means bitcoind is already stopped
            warn!(
                "Failed to send stop command (bitcoind may already be stopped): {}",
                e
            );
        }
    }


    info!(
        "Waiting for bitcoind to shut down (timeout: {}s)...",
        STOP_TIMEOUT_SECS
    );
    let stopped = wait_for_shutdown(&client, STOP_TIMEOUT_SECS).await;

    if !stopped {
        error!(
            "bitcoind did not stop within {}s timeout",
            STOP_TIMEOUT_SECS
        );
        return Err("bitcoind did not stop within timeout".into());
    }

    info!("bitcoind has stopped successfully");



    if stop_only {
        info!("Stop-only mode: bitcoind will not be restarted automatically");
        info!("To start bitcoind manually, run your usual startup command");
        return Ok(());
    }

    let restart_cmd = match restart_cmd {
        Some(cmd) if !cmd.is_empty() => cmd,
        _ => {
            info!("No restart_cmd configured in [bitcoind] section; stop-only mode");
            info!("Add a [bitcoind] section with restart_cmd to enable automatic restart");
            info!("Example:");
            info!("  [bitcoind]");
            info!("  restart_cmd = [\"/usr/bin/bitcoind\", \"-datadir=/data/bitcoin\"]");
            return Ok(());
        }
    };


    if is_systemd_managed().await {
        warn!(
            "bitcoind appears to be managed by systemd. Skipping automatic restart \
             to avoid conflicts. Use 'sudo systemctl restart bitcoind' instead, \
             or disable the systemd service if you want p2poolv2 to manage bitcoind."
        );
        return Ok(());
    }


    info!("Starting bitcoind with command: {:?}", restart_cmd);
    let binary = &restart_cmd[0];
    let args = &restart_cmd[1..];

    let child = tokio::process::Command::new(binary)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    match child {
        Ok(child) => {
            let pid = child.id().unwrap_or(0);
            info!("Spawned bitcoind process with PID {}", pid);
            // Drop child handle to detach the process
            drop(child);
        }
        Err(e) => {
            error!("Failed to spawn bitcoind: {}", e);
            return Err(format!("Failed to spawn bitcoind: {e}").into());
        }
    }


    info!(
        "Waiting for bitcoind to become responsive (timeout: {}s)...",
        START_TIMEOUT_SECS
    );
    let healthy = wait_for_healthy(&client, START_TIMEOUT_SECS).await;

    if healthy {
        info!("bitcoind is up and responsive");
        Ok(())
    } else {
        error!(
            "bitcoind did not become responsive within {}s after restart",
            START_TIMEOUT_SECS
        );
        Err("bitcoind did not become healthy after restart".into())
    }
}

/// Poll bitcoind via ping until it stops responding (connection refused / error).
/// Returns true if bitcoind stopped within the timeout, false otherwise.
async fn wait_for_shutdown(client: &BitcoindRpcClient, timeout_secs: u64) -> bool {
    let polls = timeout_secs / POLL_INTERVAL_SECS;
    for i in 0..polls {
        match client.ping().await {
            Ok(()) => {
                // Still running
                if i % 10 == 0 && i > 0 {
                    info!(
                        "bitcoind still running after {}s...",
                        i * POLL_INTERVAL_SECS
                    );
                }
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
            }
            Err(_) => {
                // Connection failed → bitcoind has stopped
                return true;
            }
        }
    }
    false
}

/// Poll bitcoind via ping until it responds successfully.
/// Returns true if bitcoind became healthy within the timeout, false otherwise.
async fn wait_for_healthy(client: &BitcoindRpcClient, timeout_secs: u64) -> bool {
    let polls = timeout_secs / POLL_INTERVAL_SECS;
    for i in 0..polls {
        match client.ping().await {
            Ok(()) => {
                // bitcoind is responsive
                return true;
            }
            Err(_) => {
                // Not yet ready
                if i % 10 == 0 && i > 0 {
                    info!(
                        "bitcoind not yet responsive after {}s...",
                        i * POLL_INTERVAL_SECS
                    );
                }
                tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
            }
        }
    }
    false
}

/// Best-effort check whether bitcoind is managed by systemd.
///
/// Returns true if `systemctl is-active bitcoind` reports "active".
/// Returns false if systemctl is not available or bitcoind is not a
/// systemd service. Does not fail on errors — this is advisory only.
async fn is_systemd_managed() -> bool {
    match tokio::process::Command::new("systemctl")
        .args(["is-active", "bitcoind"])
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let is_active = stdout.trim() == "active";
            if is_active {
                info!("Detected systemd-managed bitcoind service (active)");
            }
            is_active
        }
        Err(_) => {
            // systemctl not available or failed — assume not managed
            false
        }
    }
}
