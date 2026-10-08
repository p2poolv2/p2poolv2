// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Peer management commands that query the running node's API.

use super::PeersCommands;
use crate::commands::api_client::ApiClient;
use p2poolv2_lib::config::ApiConfig;
use std::error::Error;

/// Dispatch a peers subcommand.
pub async fn execute(
    command: &PeersCommands,
    api_config: &ApiConfig,
) -> Result<(), Box<dyn Error>> {
    match command {
        PeersCommands::Info => info(api_config).await,
        PeersCommands::Blocked => blocked_ips(api_config).await,
        PeersCommands::Block { ip } => block_ip(api_config, ip).await,
        PeersCommands::Unblock { ip } => unblock_ip(api_config, ip).await,
    }
}

/// Show connected peers.
async fn info(api_config: &ApiConfig) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);
    let response: serde_json::Value = api_client.get_json("/peers").await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// List all blocked IPs.
async fn blocked_ips(api_config: &ApiConfig) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);
    let response: serde_json::Value = api_client.get_json("/blocked_ips").await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Add an IP to the blocklist.
async fn block_ip(api_config: &ApiConfig, ip: &str) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);
    let body = serde_json::json!({"ip": ip});
    let response = api_client.post_json("/blocked_ips", &body).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Remove an IP from the blocklist.
async fn unblock_ip(api_config: &ApiConfig, ip: &str) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);
    let body = serde_json::json!({"ip": ip});
    let response = api_client.delete_json("/blocked_ips", &body).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
