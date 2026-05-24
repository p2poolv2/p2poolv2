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

//! Transaction query commands.

use super::TransactionsCommands;
use crate::commands::api_client::ApiClient;
use bitcoin::consensus::encode;
use p2poolv2_lib::config::ApiConfig;
use p2poolv2_lib::store::Store;
use serde::Serialize;
use std::error::Error;
use std::str::FromStr;

#[derive(Serialize)]
struct TransactionOutput {
    txid: String,
    version: i32,
    lock_time: String,
    inputs: Vec<InputOutput>,
    outputs: Vec<OutputOutput>,
}

#[derive(Serialize)]
struct InputOutput {
    previous_output: String,
    script_sig: String,
    sequence: u32,
}

#[derive(Serialize)]
struct OutputOutput {
    value: u64,
    script_pubkey: String,
}

#[derive(Serialize)]
struct RawTransactionOutput {
    txid: String,
    hex: String,
}

/// Execute a transactions subcommand via API.
pub async fn execute_api(
    api_config: &ApiConfig,
    command: &TransactionsCommands,
) -> Result<(), Box<dyn Error>> {
    match command {
        TransactionsCommands::Get { txid, raw } => {
            let api_client = ApiClient::new(api_config);
            let path = if *raw {
                format!("/transaction?txid={txid}&raw=true")
            } else {
                format!("/transaction?txid={txid}")
            };
            let response: serde_json::Value = api_client.get_json(&path).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
    }
}

/// Execute a transactions subcommand via direct DB access.
pub fn execute_db(store: &Store, command: &TransactionsCommands) -> Result<(), Box<dyn Error>> {
    match command {
        TransactionsCommands::Get { txid, raw } => {
            let txid =
                bitcoin::Txid::from_str(txid).map_err(|error| format!("Invalid txid: {error}"))?;
            let tx = store
                .get_tx(&txid)
                .map_err(|error| format!("Transaction not found: {error}"))?;

            if *raw {
                let raw_bytes = encode::serialize(&tx);
                let output = RawTransactionOutput {
                    txid: txid.to_string(),
                    hex: hex::encode(raw_bytes),
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                let inputs: Vec<InputOutput> = tx
                    .input
                    .iter()
                    .map(|input| InputOutput {
                        previous_output: format!(
                            "{}:{}",
                            input.previous_output.txid, input.previous_output.vout
                        ),
                        script_sig: input.script_sig.to_hex_string(),
                        sequence: input.sequence.0,
                    })
                    .collect();

                let outputs: Vec<OutputOutput> = tx
                    .output
                    .iter()
                    .map(|output| OutputOutput {
                        value: output.value.to_sat(),
                        script_pubkey: output.script_pubkey.to_hex_string(),
                    })
                    .collect();

                let output = TransactionOutput {
                    txid: txid.to_string(),
                    version: tx.version.0,
                    lock_time: format!("{}", tx.lock_time),
                    inputs,
                    outputs,
                };
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
            Ok(())
        }
    }
}
