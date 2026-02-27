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

use p2poolv2_lib::config::ApiConfig;
use serde::Deserialize;
use std::error::Error;

/// Peer info returned from the API.
#[derive(Deserialize)]
struct PeerResponse {
    peer_id: String,
}

/// Format peers as a human-readable text table.
fn format_table(peers: &[PeerResponse]) -> String {
    let mut output = String::with_capacity(peers.len() * 80);

    output.push_str(&format!("Connected peers ({}):\n", peers.len()));
    output.push_str(&format!("{}\n", "=".repeat(72)));

    if peers.is_empty() {
        output.push_str("No connected peers\n");
        return output;
    }

    for peer in peers {
        output.push_str(&format!("{}\n", peer.peer_id));
    }

    output
}

/// Execute the peers-info command by querying the running node's API.
pub async fn execute(api_config: &ApiConfig) -> Result<(), Box<dyn Error>> {
    let url = format!("http://{}:{}/peers", api_config.hostname, api_config.port);

    let client = reqwest::Client::new();
    let request = client.get(&url);

    let response = request.send().await.map_err(|error| {
        format!("Failed to connect to API at {url}: {error}. Is the node running?")
    })?;

    if !response.status().is_success() {
        return Err(format!(
            "API returned status {}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        )
        .into());
    }

    let peers: Vec<PeerResponse> = response.json().await?;
    let formatted_output = format_table(&peers);
    println!("{formatted_output}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_table_empty() {
        let peers: Vec<PeerResponse> = Vec::new();
        let output = format_table(&peers);
        assert!(output.contains("0)"));
        assert!(output.contains("No connected peers"));
    }

    #[test]
    fn test_format_table_with_peers() {
        let peers = vec![
            PeerResponse {
                peer_id: "12D3KooWAbcDef".to_string(),
            },
            PeerResponse {
                peer_id: "12D3KooWXyzGhi".to_string(),
            },
        ];
        let output = format_table(&peers);
        assert!(output.contains("2)"));
        assert!(output.contains("12D3KooWAbcDef"));
        assert!(output.contains("12D3KooWXyzGhi"));
    }
}
