// Copyright (C) 2024, 2026 P2Poolv2 Developers (see AUTHORS)
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

use bitcoin::{
    Block, CompressedPublicKey, Network,
    consensus::encode::{deserialize_hex, serialize_hex},
};
use bitcoindrpc::BitcoindRpcClient;
use p2poolv2_lib::{
    node::Config,
    shares::{
        genesis::{DEFAULT_MINER_PK, GenesisData},
        share_block::ShareBlock,
    },
};
use std::error::Error;
use tracing::info;

/// Execute the gen-genesis command.
pub async fn execute(
    config: &Config,
    public_key: Option<String>,
    network: &str,
) -> std::result::Result<(), Box<dyn Error>> {
    let rpc_client = BitcoindRpcClient::new(
        &config.bitcoinrpc.url,
        &config.bitcoinrpc.username,
        &config.bitcoinrpc.password,
    )?;

    let best_blockhash = rpc_client.getbestblockhash().await?;
    info!(%best_blockhash, "Using current best block hash");

    let bitcoin_height: u64 = rpc_client.getblockstats(&best_blockhash).await?["height"]
        .to_string()
        .parse::<u64>()
        .map_err(|e| {
            format!("Bitcoin RPC returned block stats without a valid numeric height: {e}")
        })?;

    if bitcoin_height == 0 {
        return Err("Block height must be greater than 0. Node in IBD?".into());
    }

    info!(%bitcoin_height, "Using current best block hash");

    let bitcoin_block_hex = rpc_client
        .getblock(&best_blockhash)
        .await?
        .trim_matches('"')
        .to_string();

    let bitcoin_block: Block = deserialize_hex(&bitcoin_block_hex).map_err(|e| {
        format!("Bitcoin RPC returned invalid block data for {best_blockhash}: {e}")
    })?;

    let public_key = public_key.unwrap_or_else(|| DEFAULT_MINER_PK.into());
    if public_key.parse::<CompressedPublicKey>().is_err() {
        return Err(
            "Miner public key must be a compressed public key encoded as 33-byte hex".into(),
        );
    }

    let timestamp = bitcoin_block.header.time;
    let genesis_data = GenesisData {
        public_key,
        bitcoin_block_hex,
        bitcoin_height,
        timestamp,
    };
    let network: Network = Network::from_core_arg(network).map_err(|e| {
        format!(
            "Invalid Bitcoin network '{network}'. Expected bitcoin, testnet4, signet, or regtest.\n{e}"
        )
    })?;

    let block = ShareBlock::build_genesis(&genesis_data, network)
        .map_err(|error| format!("Failed to build the genesis share block: {error}"))?;

    println!("ShareBlock hex (copy into the genesis file):");
    println!("{}", serialize_hex(&block));

    println!();
    println!(
        "Add using ({timestamp}, {bitcoin_height}, include_str!(\"{network}.rs\").into()) at fn genesis_data"
    );
    println!("See function genesis_data at p2poolv2_lib/src/shares/genesis/mod.rs");

    Ok(())
}
