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

mod cli_function;

use cli_function::{
    balance, closechannel, force_close_channel,  getaddress, getholdinvoice,
    getinvoice, listallchannels, onchaintransfer, onchaintransfer_all, openchannel, 
    payinvoice, paymentid_status, redeeminvoice,
};
use ldk_node::{
    bitcoin::{secp256k1::PublicKey, Address},
    lightning::ln::{
        channelmanager::PaymentId,
        msgs::SocketAddress,
    },
    lightning_invoice::Bolt11Invoice,
    lightning_types::payment::{PaymentHash, PaymentPreimage},
    Node, UserChannelId,
};
use std::{
    io::{self, Write},
    str::FromStr,
    sync::Arc,
};

const SERVER_NAME: &str = "Lightning Node CLI";

/// Prompts the user for input and parses it into a command and arguments.
fn get_user_input(prompt: &str) -> io::Result<(String, Option<String>, Vec<String>)> {
    let mut input = String::new();
    print!("{}", prompt);
    io::stdout().flush()?;
    io::stdin().read_line(&mut input)?;

    let input = input.trim().to_string();
    let mut parts = input.split_whitespace();
    let command = parts.next().map(str::to_string);
    let args = parts.map(str::to_string).collect();

    Ok((input, command, args))
}

/// Runs the CLI loop, processing user commands for the Lightning node.
pub async fn run_node_cli(node: Arc<Node>) {
    // Print help message on startup
    print_help();

    loop {
        match get_user_input(&format!("{}> ", SERVER_NAME)) {
            Ok((input, command, args)) => {
                let node = Arc::clone(&node); // Clone Arc only once per iteration

                let task = tokio::spawn(async move {
                    match (command.as_deref(), args.as_slice()) {
                        (Some("onchaintransfer"), [addr, sats]) => {
                            let network = node.config().network;
                            match Address::from_str(addr).and_then(|a| a.require_network(network)) {
                                Ok(dest_addr) => {
                                    match sats.parse::<u64>() {
                                        Ok(amount) => onchaintransfer(&node, &dest_addr, amount).await,
                                        Err(e) => println!("Error: Invalid amount: {}", e),
                                    }
                                }
                                Err(e) => println!("Error: Invalid address: {}", e),
                            }
                        }
                        (Some("onchaintransferall"), [addr]) => {
                            let network = node.config().network;
                            match Address::from_str(addr).and_then(|a| a.require_network(network)) {
                                Ok(dest_addr) => onchaintransfer_all(&node, &dest_addr).await,
                                Err(e) => println!("Error: Invalid address: {}", e),
                            }
                        }
                        (Some("openchannel"), [node_id, addr, sats]) => {
                            match (node_id.parse::<PublicKey>(), addr.parse::<SocketAddress>(), sats.parse::<u64>()) {
                                (Ok(id), Ok(net_addr), Ok(amount)) => {
                                    openchannel(&node, id, net_addr, amount).await
                                }
                                (Err(e), _, _) => println!("Error: Invalid node ID: {}", e),
                                (_, Err(e), _) => println!("Error: Invalid address: {}", e),
                                (_, _, Err(e)) => println!("Error: Invalid amount: {}", e),
                            }
                        }
                        (Some("balance"), []) => balance(&node).await,
                        (Some("getaddress"), []) => getaddress(&node).await,
                        (Some("listallchannels"), []) => listallchannels(&node).await,
                        (Some("paymentid_status"), [payment_id]) => {
                            match hex::decode(payment_id) {
                                Ok(bytes) if bytes.len() == 32 => {
                                    let mut array = [0u8; 32];
                                    array.copy_from_slice(&bytes);
                                    paymentid_status(&node, &PaymentId(array)).await;
                                }
                                Ok(_) => println!("Error: Payment ID must be a 32-byte hex string"),
                                Err(e) => println!("Error: Invalid payment ID: {}", e),
                            }
                        }
                        (Some("closechannel"), [chan_id, node_id]) => {
                            match (chan_id.parse::<u128>(), node_id.parse::<PublicKey>()) {
                                (Ok(id), Ok(counterparty)) => {
                                    closechannel(&node, &UserChannelId(id), counterparty).await
                                }
                                (Err(e), _) => println!("Error: Invalid channel ID: {}", e),
                                (_, Err(e)) => println!("Error: Invalid node ID: {}", e),
                            }
                        }
                        (Some("forceclosechannel"), [chan_id, node_id, reason]) => {
                            if !reason.chars().all(|c| c.is_alphanumeric() || c == '_') {
                                println!("Error: Reason must be in snake_case format");
                                return;
                            }
                            match (chan_id.parse::<u128>(), node_id.parse::<PublicKey>()) {
                                (Ok(id), Ok(counterparty)) => {
                                    force_close_channel(&node, &UserChannelId(id), counterparty, reason).await
                                }
                                (Err(e), _) => println!("Error: Invalid channel ID: {}", e),
                                (_, Err(e)) => println!("Error: Invalid node ID: {}", e),
                            }
                        }
                        (Some("getinvoice"), [amount]) => {
                            match amount.parse::<u64>() {
                                Ok(amount_sats) => getinvoice(&node, amount_sats*1000).await,
                                Err(e) => println!("Error: Invalid amount: {}", e),
                            }
                        }
                        (Some("getholdinvoice"), [amount, hash]) => {
                            match (amount.parse::<u64>(), hex::decode(hash)) {
                                (Ok(amt), Ok(bytes)) if bytes.len() == 32 => {
                                    let amount_msats = amt * 1000;
                                    let secret_hash: [u8; 32] = bytes.try_into().unwrap();
                                    getholdinvoice(&node, amount_msats, PaymentHash(secret_hash)).await;
                                }
                                (Ok(_), Ok(_)) => println!("Error: Payment hash must be a 32-byte hex string"),
                                (Ok(_), Err(e)) => println!("Error: Invalid payment hash: {}", e),
                                (Err(e), _) => println!("Error: Invalid amount: {}", e),
                            }
                        }
                        (Some("redeeminvoice"), [hash, preimage, amount]) => {
                            match (
                                hex::decode(hash),
                                hex::decode(preimage),
                                amount.parse::<u64>(),
                            ) {
                                (Ok(h_bytes), Ok(p_bytes), Ok(amt)) if h_bytes.len() == 32 && p_bytes.len() == 32 => {
                                    let secret_hash: [u8; 32] = h_bytes.try_into().unwrap();
                                    let preimage: [u8; 32] = p_bytes.try_into().unwrap();
                                    let amount_msats = amt * 1000;
                                    redeeminvoice(
                                        &node,
                                        PaymentHash(secret_hash),
                                        PaymentPreimage(preimage),
                                        amount_msats,
                                    )
                                    .await;
                                }
                                (Ok(_), Ok(_), Ok(_)) => {
                                    println!("Error: Hash and preimage must be 32-byte hex strings")
                                }
                                (Err(e), _, _) => println!("Error: Invalid payment hash: {}", e),
                                (_, Err(e), _) => println!("Error: Invalid preimage: {}", e),
                                (_, _, Err(e)) => println!("Error: Invalid amount: {}", e),
                            }
                        }
                        (Some("payinvoice"), [invoice]) => {
                            match Bolt11Invoice::from_str(invoice) {
                                Ok(inv) => payinvoice(&node, &inv).await,
                                Err(e) => println!("Error: Invalid invoice: {}", e),
                            }
                        }
                        (Some("help"), _) => print_help(),
                        (Some("exit"), _) => std::process::exit(0),
                        _ => println!("Unknown command or incorrect arguments: {}", input),
                    }
                });

                if let Err(e) = task.await {
                    println!("⚠️ Command execution failed: {:?}", e);
                }
            }
            Err(e) => {
                println!("Error reading input: {}", e);
            }
        }
    }
}

/// Prints the help message with available commands and their descriptions.
fn print_help() {
    println!("\nAvailable commands for {}:", SERVER_NAME);
    println!("  onchaintransfer <destination_address> <sats> - Transfer sats to an on-chain address");
    println!("  onchaintransferall <destination_address> - Transfer all on-chain funds to an address");
    println!("  openchannel <node_id> <listening_address> <sats> - Open a channel with a peer");
    println!("  balance - Display on-chain and channel balances");
    println!("  getaddress - Generate a new on-chain address");
    println!("  listallchannels - List all open channels");
    println!("  closechannel <channel_id> <counterparty_node_id> - Close a channel cooperatively");
    println!("  forceclosechannel <channel_id> <counterparty_node_id> <reason> - Force-close a channel");
    println!("  getinvoice <amount> - Generate a BOLT11 invoice for the specified amount");
    println!("  payinvoice <invoice> - Pay a BOLT11 invoice");
    println!("  paymentid_status <payment_id> - Check the status of a payment by ID");
    println!("  getholdinvoice <amount_sats> <payment_hash> - Generate a hold invoice");
    println!("  redeeminvoice <payment_hash> <preimage> <claimable_amount_msats> - Redeem a hold invoice");
    println!("  help - Display this help message");
    println!("  exit - Exit the CLI\n");
}