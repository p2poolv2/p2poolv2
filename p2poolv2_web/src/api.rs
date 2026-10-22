// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Client for the node's JSON API and its `/ws` feed.
//!
//! The types mirror only the fields the dashboard shows; serde ignores the
//! rest, so new fields on the node never break the app.

use base64::Engine;
use serde::{Deserialize, de::DeserializeOwned};

/// Where the API is and how to authenticate to it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Connection {
    /// API base URL without a trailing slash, e.g. `http://127.0.0.1:46884`.
    pub base: String,
    pub user: String,
    pub password: String,
}

impl Connection {
    /// Base64 `user:password`, or `None` when no user is set.
    pub fn credentials(&self) -> Option<String> {
        if self.user.is_empty() {
            return None;
        }
        Some(
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", self.user, self.password)),
        )
    }

    /// The `/ws` URL; credentials go in `?token=` because browsers cannot set
    /// headers on a WebSocket handshake.
    pub fn websocket_url(&self) -> String {
        let base = if let Some(rest) = self.base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            self.base.clone()
        };
        match self.credentials() {
            Some(token) => format!("{base}/ws?token={}", url_encode(&token)),
            None => format!("{base}/ws"),
        }
    }

    /// GET `path` (with query) and decode the JSON body.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let mut request = gloo_net::http::Request::get(&format!("{}{path}", self.base));
        if let Some(token) = self.credentials() {
            request = request.header("Authorization", &format!("Basic {token}"));
        }
        let response = request.send().await.map_err(|e| e.to_string())?;
        if !response.ok() {
            let body = response.text().await.unwrap_or_default();
            return Err(match response.status() {
                401 => "Unauthorized: set the API user and password in Settings".to_string(),
                404 if body.is_empty() => {
                    format!(
                        "{path} is not served by this node; upgrade it to a release with this endpoint"
                    )
                }
                status => format!("HTTP {status}: {body}"),
            });
        }
        response.json::<T>().await.map_err(|e| e.to_string())
    }
}

/// Percent-encode a query value (base64 and addresses only need a few).
pub fn url_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ChainInfo {
    pub chain_tip_height: Option<u32>,
    pub chain_tip_blockhash: Option<String>,
    pub total_work: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct HashratePoint {
    pub time: u64,
    pub pool_hashrate: Option<f64>,
    pub local_hashrate: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Hashrate {
    pub pool_hashrate: Option<f64>,
    pub local_hashrate: Option<f64>,
    pub network_hashrate: Option<f64>,
    pub history: Vec<HashratePoint>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Uncle {
    pub blockhash: String,
    pub miner_bitcoin_address: String,
    pub timestamp: u64,
}

/// A confirmed share, from `/shares` or a `/ws` share event.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Share {
    pub blockhash: String,
    pub height: u32,
    pub miner_bitcoin_address: String,
    pub timestamp: u64,
    #[serde(default)]
    pub uncles: Vec<Uncle>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Shares {
    pub shares: Vec<Share>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct FoundBlock {
    pub bitcoin_height: u64,
    pub bitcoin_blockhash: String,
    pub share_blockhash: String,
    pub bitcoin_time: u64,
    pub miner_bitcoin_address: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct BitcoinHeader {
    pub block_hash: String,
    pub prev_blockhash: String,
    pub merkle_root: String,
    pub time: String,
    pub bits: String,
    pub nonce: u32,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ShareDetail {
    pub blockhash: String,
    pub height: Option<u32>,
    pub validation_status: String,
    pub chain: String,
    pub parent: String,
    pub uncles: Vec<String>,
    pub miner_bitcoin_address: String,
    pub miner_address: String,
    pub bits: String,
    pub time: String,
    pub bitcoin_header: BitcoinHeader,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct MinerShare {
    pub blockhash: String,
    pub height: u32,
    pub nephew: Option<String>,
    pub difficulty: String,
    pub weight: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Miner {
    pub address: String,
    pub address_type: String,
    pub anchor_height: u32,
    pub share_count: usize,
    pub uncle_count: usize,
    pub share_fraction: f64,
    pub payout_fraction: f64,
    pub shares: Vec<MinerShare>,
}

/// A `/ws` frame: `{"topic":"Share","data":{...}}`.
#[derive(Deserialize)]
struct Event {
    topic: String,
    data: serde_json::Value,
}

/// Decode a `/ws` text frame into a share, ignoring other topics.
pub fn parse_share_event(text: &str) -> Option<Share> {
    let event: Event = serde_json::from_str(text).ok()?;
    if event.topic != "Share" {
        return None;
    }
    serde_json::from_value(event.data).ok()
}

/// The frame that subscribes to share events.
pub const SUBSCRIBE_SHARES: &str = r#"{"action":"subscribe","topic":"shares"}"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn connection(base: &str, user: &str) -> Connection {
        Connection {
            base: base.into(),
            user: user.into(),
            password: "pw".into(),
        }
    }

    #[test]
    fn test_websocket_url() {
        assert_eq!(
            connection("http://127.0.0.1:46884", "").websocket_url(),
            "ws://127.0.0.1:46884/ws"
        );
        assert_eq!(
            connection("https://pool.example", "u").websocket_url(),
            "wss://pool.example/ws?token=dTpwdw%3D%3D"
        );
    }

    #[test]
    fn test_credentials_only_with_user() {
        assert_eq!(connection("x", "").credentials(), None);
        assert_eq!(
            connection("x", "u").credentials().as_deref(),
            Some("dTpwdw==")
        );
    }

    #[test]
    fn test_parse_share_event() {
        let frame = r#"{"topic":"Share","data":{"blockhash":"ab","prev_blockhash":"cd","height":7,
            "miner_bitcoin_address":"bchtest:q","miner_address":"tp2pool:q","timestamp":5,
            "bits":1,"uncles":[]}}"#;
        let share = parse_share_event(frame).unwrap();
        assert_eq!(share.height, 7);
        assert!(parse_share_event(r#"{"topic":"Peer","data":{}}"#).is_none());
        assert!(parse_share_event("not json").is_none());
    }
}
