// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read a wallet's chain identity from a P2Poolv2 Electrum server.

use crate::ChainIdentity;
use bitcoin::{BlockHash, Network};
use electrum_client::{Client, ConfigBuilder, ElectrumApi};
use serde::Deserialize;
use std::time::Duration;

/// Time limit for connecting to the Electrum server and for each read or
/// write on the connection.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Times a failed Electrum call is retried. Zero reports the first failure.
const CALL_RETRIES: u8 = 0;

/// Errors produced when reading the chain identity from an Electrum server.
#[derive(Debug, thiserror::Error)]
pub enum ElectrumError {
    /// The URL does not use the Electrum `tcp://` or `ssl://` scheme.
    #[error("Electrum URL must be tcp://HOST:PORT or ssl://HOST:PORT")]
    InvalidUrl,
    /// The Electrum server serves a different network than the one requested.
    #[error(
        "Electrum server uses {}, but the wallet selected {}",
        .actual.to_core_arg(),
        .expected.to_core_arg()
    )]
    NetworkMismatch { expected: Network, actual: Network },
    /// The Electrum server could not be reached or answered with an error.
    #[error(transparent)]
    Client(#[from] electrum_client::Error),
    /// The `server.features` response does not have the expected fields.
    #[error(transparent)]
    Response(#[from] serde_json::Error),
}

/// The `server.features` fields that identify the share chain.
#[derive(Deserialize)]
struct ServerFeatures {
    genesis_hash: BlockHash,
    p2pool: P2PoolFeatures,
}

/// The `p2pool` object of `server.features`.
#[derive(Deserialize)]
struct P2PoolFeatures {
    network: Network,
}

/// Read the network and share chain genesis hash of a P2Poolv2 Electrum
/// server, failing unless the network is `expected`.
pub fn fetch_chain_identity(url: &str, expected: Network) -> Result<ChainIdentity, ElectrumError> {
    //* Accept only Electrum URLs, and allow a single time-limited attempt.
    if !url.starts_with("tcp://") && !url.starts_with("ssl://") {
        return Err(ElectrumError::InvalidUrl);
    }
    let config = ConfigBuilder::new()
        .timeout(Some(CONNECTION_TIMEOUT))
        .retry(CALL_RETRIES)
        .build();
    //* Connect, read `server.features` and require the expected network.
    let response = Client::from_config(url, config)?.raw_call("server.features", [])?;
    let features: ServerFeatures = serde_json::from_value(response)?;
    if features.p2pool.network != expected {
        return Err(ElectrumError::NetworkMismatch {
            expected,
            actual: features.p2pool.network,
        });
    }
    Ok(ChainIdentity {
        network: features.p2pool.network,
        sharechain_genesis_hash: features.genesis_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_rejects_a_non_electrum_url_before_connecting() {
        assert!(matches!(
            fetch_chain_identity("http://127.0.0.1:50001", Network::Signet),
            Err(ElectrumError::InvalidUrl)
        ));
    }
}
