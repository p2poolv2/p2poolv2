// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

mod atomic_swap_functions;

use crate::lightning_node;
use crate::swap::HTLCType;

use atomic_swap_functions::{
    initiate_onchain_to_lightning_swap, read_swap_from_db, redeem_swap, refund_swap,
    store_swap_to_db,
};

use crate::configuration::HtlcConfig;
use ldk_node::{
    bitcoin::{secp256k1::PublicKey, Address},
    lightning::ln::{channelmanager::PaymentId, msgs::SocketAddress},
    lightning_invoice::Bolt11Invoice,
    lightning_types::payment::{PaymentHash, PaymentPreimage},
    Node, UserChannelId,
};
use lightning_node::{
    balance, closechannel, force_close_channel, getaddress, getholdinvoice, getinvoice,
    listallchannels, onchaintransfer, onchaintransfer_all, openchannel, payinvoice,
    paymentid_status, redeeminvoice,
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

/// Prints the help message with available commands and their descriptions.
fn print_help() {
    println!("\nAvailable commands for {}:", SERVER_NAME);
    println!(
        "  onchaintransfer <destination_address> <sats> - Transfer sats to an on-chain address"
    );
    println!(
        "  onchaintransferall <destination_address> - Transfer all on-chain funds to an address"
    );
    println!("  openchannel <node_id> <listening_address> <sats> - Open a channel with a peer");
    println!("  balance - Display on-chain and channel balances");
    println!("  getaddress - Generate a new on-chain address");
    println!("  listallchannels - List all open channels");
    println!("  closechannel <channel_id> <counterparty_node_id> - Close a channel cooperatively");
    println!(
        "  forceclosechannel <channel_id> <counterparty_node_id> <reason> - Force-close a channel"
    );
    println!("  getinvoice <amount> - Generate a BOLT11 invoice for the specified amount");
    println!("  payinvoice <invoice> - Pay a BOLT11 invoice");
    println!("  paymentid_status <payment_id> - Check the status of a payment by ID");
    println!("  getholdinvoice <amount_sats> <payment_hash> - Generate a hold invoice");
    println!("  redeeminvoice <payment_hash> <preimage> <claimable_amount_msats> - Redeem a hold invoice");
    println!("  fromchainswap - Initiate an on-chain to Lightning atomic swap interactively");
    println!("  swapdb - Store a swap to the db or read a swap from the db interactively");
    println!("  redeemswap - Redeem a swap by providing swap id and BOLT11 invoice");
    println!("  refundswap - Refund a swap by providing swap id");
    println!("  help - Display this help message");
    println!("  exit - Exit the CLI\n");
}

/// Runs the CLI loop, processing user commands for the Lightning node.
pub async fn run_node_cli(node: Arc<Node>, htlc_config: HtlcConfig) {
    // Print help message on startup
    print_help();

    loop {
        match get_user_input(&format!("{}> ", SERVER_NAME)) {
            Ok((input, command, args)) => {
                let node = Arc::clone(&node); // Clone Arc only once per iteration
                let db_path = htlc_config.db_path.clone();
                let htlc_config = htlc_config.clone();
                match (command.as_deref(), args.as_slice()) {
                    (Some("onchaintransfer"), [addr, sats]) => {
                        let network = node.config().network;
                        let result = Address::from_str(addr)
                            .and_then(|a| a.require_network(network))
                            .map_err(|e| format!("Invalid address: {}", e))
                            .and_then(|dest_addr| {
                                sats.parse::<u64>()
                                    .map_err(|e| format!("Invalid amount: {}", e))
                                    .map(|amount| (dest_addr, amount))
                            });

                        match result {
                            Ok((dest_addr, amount)) => {
                                match onchaintransfer(&node, &dest_addr, amount).await {
                                    Ok(txid) => println!("Transaction sent successfully: {}", txid),
                                    Err(e) => println!("On-chain transfer failed: {}", e),
                                }
                            }
                            Err(e) => println!("Error: {}", e),
                        }
                    }
                    (Some("onchaintransferall"), [addr]) => {
                        let network = node.config().network;
                        match Address::from_str(addr).and_then(|a| a.require_network(network)) {
                            Ok(dest_addr) => match onchaintransfer_all(&node, &dest_addr).await {
                                Ok(txid) => println!("Transaction sent successfully: {}", txid),
                                Err(e) => println!("On-chain transfer all failed: {}", e),
                            },
                            Err(e) => println!("Error: Invalid address: {}", e),
                        }
                    }
                    (Some("openchannel"), [node_id, addr, sats]) => {
                        match (
                            node_id.parse::<PublicKey>(),
                            addr.parse::<SocketAddress>(),
                            sats.parse::<u64>(),
                        ) {
                            (Ok(id), Ok(net_addr), Ok(amount)) => {
                                match openchannel(&node, id, net_addr, amount).await {
                                    Ok(channel_id) => {
                                        println!("Channel opened successfully: {:?}", channel_id)
                                    }
                                    Err(e) => println!("Error opening channel: {}", e),
                                }
                            }
                            (Err(e), _, _) => println!("Error: Invalid node ID: {}", e),
                            (_, Err(e), _) => println!("Error: Invalid address: {}", e),
                            (_, _, Err(e)) => println!("Error: Invalid amount: {}", e),
                        }
                    }
                    (Some("balance"), []) => match balance(&node).await {
                        Ok((onchain, lightning)) => {
                            println!("On-Chain Balance: {} sats", onchain);
                            println!("Lightning Balance: {} sats", lightning);
                        }
                        Err(e) => println!("Error getting balances: {}", e),
                    },
                    (Some("getaddress"), []) => match getaddress(&node).await {
                        Ok(addr) => println!("Address: {}", addr),
                        Err(e) => println!("Error getting address: {}", e),
                    },
                    (Some("listallchannels"), []) => {
                        match listallchannels(&node).await {
                            Ok(_) => {} // Output handled by listallchannels via println!
                            Err(e) => println!("Error listing channels: {}", e),
                        }
                    }
                    (Some("paymentid_status"), [payment_id]) => match hex::decode(payment_id) {
                        Ok(bytes) if bytes.len() == 32 => {
                            let mut array = [0u8; 32];
                            array.copy_from_slice(&bytes);
                            match paymentid_status(&node, &PaymentId(array)).await {
                                Ok(_) => {} // Output handled by paymentid_status via println!
                                Err(e) => println!("Error checking payment status: {}", e),
                            }
                        }
                        Ok(_) => println!("Error: Payment ID must be a 32-byte hex string"),
                        Err(e) => println!("Error: Invalid payment ID: {}", e),
                    },
                    (Some("closechannel"), [chan_id, node_id]) => {
                        match (chan_id.parse::<u128>(), node_id.parse::<PublicKey>()) {
                            (Ok(id), Ok(counterparty)) => {
                                match closechannel(&node, &UserChannelId(id), counterparty).await {
                                    Ok(_) => println!("Channel closed successfully"),
                                    Err(e) => println!("Error closing channel: {}", e),
                                }
                            }
                            (Err(e), _) => println!("Error: Invalid channel ID: {}", e),
                            (_, Err(e)) => println!("Error: Invalid node ID: {}", e),
                        }
                    }
                    (Some("forceclosechannel"), [chan_id, node_id, reason]) => {
                        if !reason.chars().all(|c| c.is_alphanumeric() || c == '_') {
                            println!("Error: Reason must be in snake_case format");
                            continue;
                        }
                        match (chan_id.parse::<u128>(), node_id.parse::<PublicKey>()) {
                            (Ok(id), Ok(counterparty)) => {
                                match force_close_channel(
                                    &node,
                                    &UserChannelId(id),
                                    counterparty,
                                    reason,
                                )
                                .await
                                {
                                    Ok(_) => println!("Channel force-closed successfully"),
                                    Err(e) => println!("Error force-closing channel: {}", e),
                                }
                            }
                            (Err(e), _) => println!("Error: Invalid channel ID: {}", e),
                            (_, Err(e)) => println!("Error: Invalid node ID: {}", e),
                        }
                    }
                    (Some("getinvoice"), [amount]) => match amount.parse::<u64>() {
                        Ok(amount_sats) => match getinvoice(&node, amount_sats * 1000).await {
                            Ok(invoice) => println!("Invoice: {}", invoice),
                            Err(e) => println!("Error creating invoice: {}", e),
                        },
                        Err(_) => println!("Error: Invalid amount"),
                    },
                    (Some("getholdinvoice"), [amount, hash]) => {
                        match (amount.parse::<u64>(), hex::decode(hash)) {
                            (Ok(amt), Ok(bytes)) if bytes.len() == 32 => {
                                let amount_msats = amt * 1000;
                                let secret_hash: [u8; 32] = bytes.try_into().unwrap();
                                match getholdinvoice(&node, amount_msats, PaymentHash(secret_hash))
                                    .await
                                {
                                    Ok(invoice) => println!("Hold invoice: {}", invoice),
                                    Err(e) => println!("Error creating hold invoice: {}", e),
                                }
                            }
                            (Ok(_), Ok(_)) => {
                                println!("Error: Payment hash must be a 32-byte hex string")
                            }
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
                            (Ok(h_bytes), Ok(p_bytes), Ok(amt))
                                if h_bytes.len() == 32 && p_bytes.len() == 32 =>
                            {
                                let secret_hash: [u8; 32] = h_bytes.try_into().unwrap();
                                let preimage: [u8; 32] = p_bytes.try_into().unwrap();
                                let amount_msats = amt * 1000;
                                match redeeminvoice(
                                    &node,
                                    PaymentHash(secret_hash),
                                    PaymentPreimage(preimage),
                                    amount_msats,
                                )
                                .await
                                {
                                    Ok(_) => println!("Invoice redeemed successfully"),
                                    Err(e) => println!("Error redeeming invoice: {}", e),
                                }
                            }
                            (Ok(_), Ok(_), Ok(_)) => {
                                println!("Error: Hash and preimage must be 32-byte hex strings")
                            }
                            (Err(e), _, _) => println!("Error: Invalid payment hash: {}", e),
                            (_, Err(e), _) => println!("Error: Invalid preimage: {}", e),
                            (_, _, Err(e)) => println!("Error: Invalid amount: {}", e),
                        }
                    }
                    (Some("payinvoice"), [invoice]) => match Bolt11Invoice::from_str(invoice) {
                        Ok(inv) => match payinvoice(&node, &inv).await {
                            Ok(payment_id) => {
                                println!("Payment sent. Payment ID: {:?}", payment_id)
                            }
                            Err(e) => println!("Payment failed: {}", e),
                        },
                        Err(e) => println!("Error: Invalid invoice: {}", e),
                    },
                    (Some("fromchainswap"), []) => {
                        // Interactive prompt for swap creation
                        let mut input = String::new();
                        print!("Enter initiator pubkey: ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut input).unwrap();
                        let initiator_pubkey = input.trim().to_string();

                        input.clear();
                        print!("Enter responder pubkey: ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut input).unwrap();
                        let responder_pubkey = input.trim().to_string();

                        input.clear();
                        print!("Enter timelock (u64): ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut input).unwrap();
                        let timelock = match input.trim().parse::<u64>() {
                            Ok(t) => t,
                            Err(_) => {
                                println!("Invalid timelock");
                                continue;
                            }
                        };

                        input.clear();
                        print!("Enter amount (sats): ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut input).unwrap();
                        let from_amount = match input.trim().parse::<u64>() {
                            Ok(a) => a,
                            Err(_) => {
                                println!("Invalid amount");
                                continue;
                            }
                        };

                        input.clear();
                        print!("Enter expected received amount (sats): ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut input).unwrap();
                        let to_amount = match input.trim().parse::<u64>() {
                            Ok(a) => a,
                            Err(_) => {
                                println!("Invalid expected received amount");
                                continue;
                            }
                        };

                        // htlc_type is always P2TR
                        let htlc_type = HTLCType::P2tr2;
                        initiate_onchain_to_lightning_swap(
                            &node,
                            &db_path,
                            initiator_pubkey,
                            responder_pubkey,
                            timelock,
                            from_amount,
                            htlc_type,
                            to_amount,
                        )
                        .await;
                        println!("On-chain to Lightning swap initiated successfully");
                    }
                    (Some("swapdb"), []) => {
                        let mut input = String::new();
                        print!("Type 'store' to store a swap or 'read' to read a swap: ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut input).unwrap();
                        let action = input.trim().to_lowercase();

                        if action == "store" {
                            input.clear();
                            print!("Enter initiator pubkey: ");
                            io::stdout().flush().unwrap();
                            io::stdin().read_line(&mut input).unwrap();
                            let initiator_pubkey = input.trim().to_string();

                            input.clear();
                            print!("Enter responder pubkey: ");
                            io::stdout().flush().unwrap();
                            io::stdin().read_line(&mut input).unwrap();
                            let responder_pubkey = input.trim().to_string();

                            input.clear();
                            print!("Enter timelock (u64): ");
                            io::stdout().flush().unwrap();
                            io::stdin().read_line(&mut input).unwrap();
                            let timelock = match input.trim().parse::<u64>() {
                                Ok(t) => t,
                                Err(_) => {
                                    println!("Invalid timelock");
                                    continue;
                                }
                            };

                            input.clear();
                            print!("Enter amount (sats): ");
                            io::stdout().flush().unwrap();
                            io::stdin().read_line(&mut input).unwrap();
                            let from_amount = match input.trim().parse::<u64>() {
                                Ok(a) => a,
                                Err(_) => {
                                    println!("Invalid amount");
                                    continue;
                                }
                            };

                            input.clear();
                            print!("Enter expected received amount (sats): ");
                            io::stdout().flush().unwrap();
                            io::stdin().read_line(&mut input).unwrap();
                            let to_amount = match input.trim().parse::<u64>() {
                                Ok(a) => a,
                                Err(_) => {
                                    println!("Invalid expected received amount");
                                    continue;
                                }
                            };

                            input.clear();
                            print!("Enter payment hash: ");
                            io::stdout().flush().unwrap();
                            io::stdin().read_line(&mut input).unwrap();
                            let payment_hash = input.trim().to_string();

                            let htlc_type = HTLCType::P2tr2;
                            store_swap_to_db(
                                &db_path,
                                initiator_pubkey,
                                responder_pubkey,
                                timelock,
                                from_amount,
                                htlc_type,
                                to_amount,
                                payment_hash,
                            )
                            .await;
                            println!("Swap stored successfully");
                        } else if action == "read" {
                            input.clear();
                            print!("Enter swap id: ");
                            io::stdout().flush().unwrap();
                            io::stdin().read_line(&mut input).unwrap();
                            let swap_id = input.trim().to_string();
                            read_swap_from_db(&db_path, &swap_id).await;
                        } else {
                            println!("Unknown action: {}. Use 'store' or 'read'", action);
                        }
                    }
                    (Some("redeemswap"), []) => {
                        let mut input = String::new();
                        print!("Enter swap id: ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut input).unwrap();
                        let swap_id = input.trim().to_string();

                        input.clear();
                        print!("Enter BOLT11 invoice: ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut input).unwrap();
                        let invoice_str = input.trim().to_string();

                        match Bolt11Invoice::from_str(&invoice_str) {
                            Ok(invoice) => {
                                redeem_swap(
                                    &node,
                                    &htlc_config,
                                    &htlc_config.db_path,
                                    &swap_id,
                                    &invoice,
                                )
                                .await;
                                println!("Swap redeemed successfully");
                            }
                            Err(e) => println!("Invalid invoice: {}", e),
                        }
                    }
                    (Some("refundswap"), []) => {
                        let mut input = String::new();
                        print!("Enter swap id: ");
                        io::stdout().flush().unwrap();
                        io::stdin().read_line(&mut input).unwrap();
                        let swap_id = input.trim().to_string();

                        refund_swap(&node, &htlc_config, &htlc_config.db_path, &swap_id).await;
                        println!("Swap refunded successfully");
                    }
                    (Some("help"), _) => print_help(),
                    (Some("exit"), _) => std::process::exit(0),
                    _ => println!("Unknown command or incorrect arguments: {}", input),
                }
            }
            Err(e) => {
                println!("Error reading input: {}", e);
            }
        }
    }
}
