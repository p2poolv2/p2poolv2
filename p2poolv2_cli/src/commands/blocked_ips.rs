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
