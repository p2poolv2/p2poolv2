// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::commands::api_client::ApiClient;
use p2poolv2_lib::config::ApiConfig;
use std::error::Error;

/// List all blocked IPs.
pub async fn list(api_config: &ApiConfig) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);
    let response: serde_json::Value = api_client.get_json("/blocked_ips").await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Add an IP to the blocklist.
pub async fn block(api_config: &ApiConfig, ip: &str) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);
    let body = serde_json::json!({"ip": ip});
    let response = api_client.post_json("/blocked_ips", &body).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Remove an IP from the blocklist.
pub async fn unblock(api_config: &ApiConfig, ip: &str) -> Result<(), Box<dyn Error>> {
    let api_client = ApiClient::new(api_config);
    let body = serde_json::json!({"ip": ip});
    let response = api_client.delete_json("/blocked_ips", &body).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
