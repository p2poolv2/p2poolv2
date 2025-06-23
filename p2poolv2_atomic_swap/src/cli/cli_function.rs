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

use ldk_node::lightning::ln::channelmanager::PaymentId;
use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
pub use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};
use ldk_node::{
    bitcoin::{secp256k1::PublicKey, Address},
    lightning::ln::msgs::SocketAddress,
};
use ldk_node::{Node, UserChannelId};

/// Default invoice expiry time in seconds (24 hours)
const DEFAULT_EXPIRY_SECS: u32 = 86_400;
/// Default invoice description
const DEFAULT_INVOICE_DESCRIPTION: &str = "P2Poolv2 Invoice";

// TODO: Add peer management (connect, list, disconnect)

/// Handles errors uniformly by printing error messages.
fn handle_error<E: std::fmt::Debug>(context: &str, error: E) {
    println!("Error {}: {:?}", context, error);
}

/// Sends an on-chain transfer to a specified address.
pub(crate) async fn onchaintransfer(node: &Node, destination_address: &Address, amount_sats: u64) {
    match node
        .onchain_payment()
        .send_to_address(destination_address, amount_sats, None)
    {
        Ok(txid) => println!("On-chain transfer successful. Transaction ID: {}", txid),
        Err(e) => handle_error("sending on-chain transfer", e),
    };
}

/// Sends all available on-chain funds to a specified address.
pub(crate) async fn onchaintransfer_all(node: &Node, destination: &Address) {
    match node
        .onchain_payment()
        .send_all_to_address(destination, false, None)
    {
        Ok(txid) => println!("On-chain transfer successful. Transaction ID: {}", txid),
        Err(e) => handle_error("sending all on-chain funds", e),
    }
}

// Opens a new Lightning channel with a peer.
pub(crate) async fn openchannel(
    node: &Node,
    node_id: PublicKey,
    socket_addr: SocketAddress,
    channel_amount_sats: u64,
) {
    match node.open_channel(node_id, socket_addr, channel_amount_sats, None, None) {
        Ok(channel_id) => println!("Channel opened successfully. Channel ID: {:?}", channel_id),
        Err(e) => handle_error("opening channel", e),
    }
}

// Prints the node's on-chain and Lightning balances.
pub(crate) async fn balance(node: &Node) {
    let balances = node.list_balances();
    println!(
        "On-Chain Balance: {} sats",
        balances.total_onchain_balance_sats
    );
    println!(
        "Lightning Balance: {} sats",
        balances.total_lightning_balance_sats
    );
}

/// Generates a new on-chain funding address.
pub(crate) async fn getaddress(node: &Node) {
    match node.onchain_payment().new_address() {
        Ok(addr) => println!("Funding Address: {}", addr),
        Err(e) => handle_error("getting funding address", e),
    }
}

pub(crate) async fn listallchannels(node: &Node) {
    let channels = node.list_channels();
    if channels.is_empty() {
        println!("No channels found.");
    } else {
        println!("Channels:");
        for channel in channels.iter() {
            println!("--------------------------------------------");
            println!("Channel ID: {}", channel.channel_id);
            println!("User Channel ID: {:?}", channel.user_channel_id);
            println!("Channel Counterparty: {}", channel.counterparty_node_id);
            println!("Channel Value: {} sats", channel.channel_value_sats);
            println!(
                "Spendable (Outbound) Balance: {} sats",
                channel.outbound_capacity_msat / 1000
            );
            println!(
                "Receivable (Inbound) Balance: {} sats",
                channel.inbound_capacity_msat / 1000
            );
            println!("Channel Ready?: {}", channel.is_channel_ready);
            println!("Is Usable?: {}", channel.is_usable);
            println!(
                "Max Htlc Spendable: {} sats",
                channel.counterparty_outbound_htlc_maximum_msat.unwrap() / 1000
            );
            if !channel.is_usable {
                println!("Channel not usable. Possible reasons:");
                if !channel.is_channel_ready {
                    println!("- Channel not yet ready (still confirming/pending)");
                }
                if channel.outbound_capacity_msat == 0 {
                    println!("- No outbound capacity");
                }
            }
        }
        println!("--------------------------------------------");
    }
}

/// Closes a Lightning channel cooperatively.
pub(crate) async fn closechannel(
    node: &Node,
    channel_id: &UserChannelId,
    counterparty_node_id: PublicKey,
) {
    match node.close_channel(channel_id, counterparty_node_id) {
        Ok(_) => println!("Channel closed successfully."),
        Err(e) => handle_error("Error closing channel", e),
    };
}

/// Force-closes a Lightning channel with a reason
pub(crate) async fn force_close_channel(
    node: &Node,
    channel_id: &UserChannelId,
    counterparty_node_id: PublicKey,
    reason: &str,
) {
    // Ensure the reason is in snake_case or camelCase format
    if !reason
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c.is_lowercase() || c.is_uppercase())
    {
        println!("Error: 'reason' must be in snake_case or camelCase format.");
        return;
    }

    match node.force_close_channel(
        channel_id,
        counterparty_node_id,
        Option::from(String::from(reason)),
    ) {
        Ok(_) => println!("Channel force closed successfully."),
        Err(e) => handle_error("Error force closing channel", e),
    };
}

/// Generates a new Bolt11 invoice for a specified amount.
pub(crate) async fn getinvoice(node: &Node, amount_msats: u64) {
    let bolt11payment = node.bolt11_payment();
    let description = Description::new(DEFAULT_INVOICE_DESCRIPTION.to_string()).unwrap();
    let description = Bolt11InvoiceDescription::Direct(description);
    match bolt11payment.receive(amount_msats, &description, DEFAULT_EXPIRY_SECS) {
        Ok(invoice) => {
            println!("Invoice: {}", invoice);
        }
        Err(e) => handle_error("Creating invoice", e),
    }
}

/// Generates a hold invoice with a specified payment hash.
pub(crate) async fn getholdinvoice(node: &Node, amount_msats: u64, payment_hash: PaymentHash) {
    let bolt11_payment = node.bolt11_payment();
    let description = Description::new("Test invoice".to_string()).unwrap();
    let description = Bolt11InvoiceDescription::Direct(description);
    match bolt11_payment.receive_for_hash(
        amount_msats,
        &description,
        DEFAULT_EXPIRY_SECS,
        payment_hash,
    ) {
        Ok(invoice) => {
            println!("Hold Invoice: {}", invoice);
        }
        Err(e) => {
            handle_error("Creating hold invoice", e);
        }
    }
}

/// Redeems a hold invoice with the provided preimage.
pub(crate) async fn redeeminvoice(
    node: &Node,
    payment_hash: PaymentHash,
    preimage: PaymentPreimage,
    claimable_amount_msats: u64,
) {
    let bolt11_payment = node.bolt11_payment();
    match bolt11_payment.claim_for_hash(payment_hash, claimable_amount_msats, preimage) {
        Ok(_) => println!("Invoice redeemed successfully."),
        Err(e) => handle_error("Redeeming invoice", e),
    };
}

/// Pays a Bolt11 invoice
pub(crate) async fn payinvoice(node: &Node, invoice: &Bolt11Invoice) {
    let bolt11payment = node.bolt11_payment();
    match bolt11payment.send(invoice, None) {
        Ok(payment_id) => {
            println!("Payment send. Payment Id: {}", payment_id);
        }
        Err(e) => {
            handle_error("Paying invoice", e);
        }
    }
}

/// Retrieves and displays payment status by payment ID.
pub(crate) async fn paymentid_status(node: &Node, payment_id: &PaymentId) {
    match node.payment(&payment_id) {
        Some(payment_details) => {
            println!("Payment Details:");
            println!("ID: {}", payment_details.id);
            println!("Kind: {:?}", payment_details.kind);
            println!("Amount (msat): {:?}", payment_details.amount_msat);
            println!("Fee Paid (msat): {:?}", payment_details.fee_paid_msat);
            println!("Direction: {:?}", payment_details.direction);
            println!("Status: {:?}", payment_details.status);
            println!(
                "Latest Update Timestamp: {}",
                payment_details.latest_update_timestamp
            );
        }
        None => {
            println!("No payment found with this payment id");
        }
    }
}
