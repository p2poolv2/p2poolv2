use ldk_node::lightning::ln::channelmanager::PaymentId;
use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
pub use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};
use ldk_node::{
    bitcoin::{secp256k1::PublicKey, Address, Txid},
    lightning::ln::msgs::SocketAddress,
};
use ldk_node::{Node, UserChannelId};
use log::{error, info};
use thiserror::Error;

pub mod checks;
pub mod event_handler;

#[derive(Error, Debug)]
pub enum NodeError {
    #[error("Failed to send on-chain transfer: {0}")]
    OnchainTransferError(String),
    #[error("Failed to send all on-chain funds: {0}")]
    OnchainTransferAllError(String),
    #[error("Failed to open channel: {0}")]
    OpenChannelError(String),
    #[error("Failed to get funding address: {0}")]
    GetAddressError(String),
    #[error("Failed to close channel: {0}")]
    CloseChannelError(String),
    #[error("Invalid reason format: {0}")]
    InvalidReasonFormat(String),
    #[error("Failed to force close channel: {0}")]
    ForceCloseChannelError(String),
    #[error("Failed to create invoice: {0}")]
    CreateInvoiceError(String),
    #[error("Failed to create hold invoice: {0}")]
    CreateHoldInvoiceError(String),
    #[error("Failed to redeem invoice: {0}")]
    RedeemInvoiceError(String),
    #[error("Failed to pay invoice: {0}")]
    PayInvoiceError(String),
    #[error("Failed to create invoice description: {0}")]
    DescriptionError(String),
}

/// Default invoice expiry time in seconds (24 hours)
const DEFAULT_EXPIRY_SECS: u32 = 86_400;
/// Default invoice description
const DEFAULT_INVOICE_DESCRIPTION: &str = "P2Poolv2 Invoice";

/// Sends an on-chain transfer to a specified address.
pub(crate) async fn onchaintransfer(
    node: &Node,
    destination_address: &Address,
    amount_sats: u64,
) -> Result<Txid, NodeError> {
    info!(
        "Sending on-chain transfer of {} sats to {}",
        amount_sats, destination_address
    );
    match node
        .onchain_payment()
        .send_to_address(destination_address, amount_sats, None)
    {
        Ok(txid) => {
            info!("On-chain transfer successful. Transaction ID: {}", txid);
            Ok(txid)
        }
        Err(e) => {
            error!("Error sending on-chain transfer: {:?}", e);
            Err(NodeError::OnchainTransferError(e.to_string()))
        }
    }
}

/// Sends all available on-chain funds to a specified address.
pub(crate) async fn onchaintransfer_all(
    node: &Node,
    destination: &Address,
) -> Result<Txid, NodeError> {
    info!("Sending all on-chain funds to {}", destination);
    match node
        .onchain_payment()
        .send_all_to_address(destination, false, None)
    {
        Ok(txid) => {
            info!("On-chain transfer successful. Transaction ID: {}", txid);
            Ok(txid)
        }
        Err(e) => {
            error!("Error sending all on-chain funds: {:?}", e);
            Err(NodeError::OnchainTransferAllError(e.to_string()))
        }
    }
}

/// Opens a new Lightning channel with a peer.
pub(crate) async fn openchannel(
    node: &Node,
    node_id: PublicKey,
    socket_addr: SocketAddress,
    channel_amount_sats: u64,
) -> Result<UserChannelId, NodeError> {
    info!(
        "Opening channel with node {} at {} for {} sats",
        node_id, socket_addr, channel_amount_sats
    );
    match node.open_channel(node_id, socket_addr, channel_amount_sats, None, None) {
        Ok(channel_id) => {
            info!("Channel opened successfully. Channel ID: {:?}", channel_id);
            Ok(channel_id)
        }
        Err(e) => {
            error!("Error opening channel: {:?}", e);
            Err(NodeError::OpenChannelError(e.to_string()))
        }
    }
}

/// Prints the node's on-chain and Lightning balances.
pub(crate) async fn balance(node: &Node) -> Result<(u64, u64), NodeError> {
    let balances = node.list_balances();
    info!(
        "On-Chain Balance: {} sats",
        balances.total_onchain_balance_sats
    );
    info!(
        "Lightning Balance: {} sats",
        balances.total_lightning_balance_sats
    );
    Ok((
        balances.total_onchain_balance_sats,
        balances.total_lightning_balance_sats,
    ))
}

/// Generates a new on-chain funding address.
pub(crate) async fn getaddress(node: &Node) -> Result<Address, NodeError> {
    info!("Generating new on-chain funding address");
    match node.onchain_payment().new_address() {
        Ok(addr) => {
            info!("Generated funding address: {}", addr);
            Ok(addr)
        }
        Err(e) => {
            error!("Error getting funding address: {:?}", e);
            Err(NodeError::GetAddressError(e.to_string()))
        }
    }
}

/// Lists all Lightning channels.
pub(crate) async fn listallchannels(node: &Node) -> Result<(), NodeError> {
    let channels = node.list_channels();
    if channels.is_empty() {
        info!("No channels found.");
    } else {
        info!("Listing channels:");
        for channel in channels.iter() {
            info!("--------------------------------------------");
            info!("Channel ID: {}", channel.channel_id);
            info!("User Channel ID: {:?}", channel.user_channel_id);
            info!("Channel Counterparty: {}", channel.counterparty_node_id);
            info!("Channel Value: {} sats", channel.channel_value_sats);
            info!(
                "Spendable (Outbound) Balance: {} sats",
                channel.outbound_capacity_msat / 1000
            );
            info!(
                "Receivable (Inbound) Balance: {} sats",
                channel.inbound_capacity_msat / 1000
            );
            info!("Channel Ready?: {}", channel.is_channel_ready);
            info!("Is Usable?: {}", channel.is_usable);
            info!(
                "Max Htlc Spendable: {} sats",
                channel.counterparty_outbound_htlc_maximum_msat.unwrap() / 1000
            );
            if !channel.is_usable {
                info!("Channel not usable. Possible reasons:");
                if !channel.is_channel_ready {
                    info!("- Channel not yet ready (still confirming/pending)");
                }
                if channel.outbound_capacity_msat == 0 {
                    info!("- No outbound capacity");
                }
            }
        }
        info!("--------------------------------------------");
    }
    Ok(())
}

/// Closes a Lightning channel cooperatively.
pub(crate) async fn closechannel(
    node: &Node,
    channel_id: &UserChannelId,
    counterparty_node_id: PublicKey,
) -> Result<(), NodeError> {
    info!(
        "Closing channel with ID {:?} and counterparty {}",
        channel_id, counterparty_node_id
    );
    match node.close_channel(channel_id, counterparty_node_id) {
        Ok(_) => {
            info!("Channel closed successfully.");
            Ok(())
        }
        Err(e) => {
            error!("Error closing channel: {:?}", e);
            Err(NodeError::CloseChannelError(e.to_string()))
        }
    }
}

/// Force-closes a Lightning channel with a reason.
pub(crate) async fn force_close_channel(
    node: &Node,
    channel_id: &UserChannelId,
    counterparty_node_id: PublicKey,
    reason: &str,
) -> Result<(), NodeError> {
    // Ensure the reason is in snake_case or camelCase format
    if !reason
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c.is_lowercase() || c.is_uppercase())
    {
        error!(
            "Invalid reason format: '{}'. Must be snake_case or camelCase.",
            reason
        );
        return Err(NodeError::InvalidReasonFormat(
            "Reason must be in snake_case or camelCase format".to_string(),
        ));
    }

    info!(
        "Force-closing channel with ID {:?} and counterparty {}, reason: {}",
        channel_id, counterparty_node_id, reason
    );
    match node.force_close_channel(
        channel_id,
        counterparty_node_id,
        Option::from(String::from(reason)),
    ) {
        Ok(_) => {
            info!("Channel force closed successfully.");
            Ok(())
        }
        Err(e) => {
            error!("Error force closing channel: {:?}", e);
            Err(NodeError::ForceCloseChannelError(e.to_string()))
        }
    }
}

/// Generates a new Bolt11 invoice for a specified amount.
pub(crate) async fn getinvoice(node: &Node, amount_msats: u64) -> Result<Bolt11Invoice, NodeError> {
    info!("Generating Bolt11 invoice for {} msats", amount_msats);
    let bolt11payment = node.bolt11_payment();
    let description = Description::new(DEFAULT_INVOICE_DESCRIPTION.to_string()).map_err(|e| {
        error!("Failed to create invoice description: {}", e);
        NodeError::DescriptionError(e.to_string())
    })?;
    let description = Bolt11InvoiceDescription::Direct(description);
    match bolt11payment.receive(amount_msats, &description, DEFAULT_EXPIRY_SECS) {
        Ok(invoice) => {
            info!("Generated invoice: {}", invoice);
            Ok(invoice)
        }
        Err(e) => {
            error!("Error creating invoice: {:?}", e);
            Err(NodeError::CreateInvoiceError(e.to_string()))
        }
    }
}

/// Generates a hold invoice with a specified payment hash.
pub(crate) async fn getholdinvoice(
    node: &Node,
    amount_msats: u64,
    payment_hash: PaymentHash,
) -> Result<Bolt11Invoice, NodeError> {
    info!(
        "Generating hold invoice for {} msats with payment hash {:?}",
        amount_msats, payment_hash
    );
    let bolt11_payment = node.bolt11_payment();
    let description = Description::new("Test invoice".to_string()).map_err(|e| {
        error!("Failed to create hold invoice description: {}", e);
        NodeError::DescriptionError(e.to_string())
    })?;
    let description = Bolt11InvoiceDescription::Direct(description);
    match bolt11_payment.receive_for_hash(
        amount_msats,
        &description,
        DEFAULT_EXPIRY_SECS,
        payment_hash,
    ) {
        Ok(invoice) => {
            info!("Generated hold invoice: {}", invoice);
            Ok(invoice)
        }
        Err(e) => {
            error!("Error creating hold invoice: {:?}", e);
            Err(NodeError::CreateHoldInvoiceError(e.to_string()))
        }
    }
}

/// Redeems a hold invoice with the provided preimage.
pub(crate) async fn redeeminvoice(
    node: &Node,
    payment_hash: PaymentHash,
    preimage: PaymentPreimage,
    claimable_amount_msats: u64,
) -> Result<(), NodeError> {
    info!(
        "Redeeming invoice with payment hash {:?} and amount {} msats",
        payment_hash, claimable_amount_msats
    );
    let bolt11_payment = node.bolt11_payment();
    match bolt11_payment.claim_for_hash(payment_hash, claimable_amount_msats, preimage) {
        Ok(_) => {
            info!("Invoice redeemed successfully.");
            Ok(())
        }
        Err(e) => {
            error!("Error redeeming invoice: {:?}", e);
            Err(NodeError::RedeemInvoiceError(e.to_string()))
        }
    }
}

/// Pays a Bolt11 invoice.
pub(crate) async fn payinvoice(
    node: &Node,
    invoice: &Bolt11Invoice,
) -> Result<PaymentId, NodeError> {
    info!("Paying invoice: {}", invoice);
    let bolt11payment = node.bolt11_payment();
    match bolt11payment.send(invoice, None) {
        Ok(payment_id) => {
            info!("Payment sent. Payment Id: {}", payment_id);
            Ok(payment_id)
        }
        Err(e) => {
            error!("Error paying invoice: {:?}", e);
            Err(NodeError::PayInvoiceError(e.to_string()))
        }
    }
}

/// Retrieves and displays payment status by payment ID.
pub(crate) async fn paymentid_status(node: &Node, payment_id: &PaymentId) -> Result<(), NodeError> {
    info!("Retrieving payment status for payment ID: {}", payment_id);
    match node.payment(payment_id) {
        Some(payment_details) => {
            info!("Payment Details:");
            info!("ID: {}", payment_details.id);
            info!("Kind: {:?}", payment_details.kind);
            info!("Amount (msat): {:?}", payment_details.amount_msat);
            info!("Fee Paid (msat): {:?}", payment_details.fee_paid_msat);
            info!("Direction: {:?}", payment_details.direction);
            info!("Status: {:?}", payment_details.status);
            info!(
                "Latest Update Timestamp: {}",
                payment_details.latest_update_timestamp
            );
            Ok(())
        }
        None => {
            info!("No payment found with payment ID: {}", payment_id);
            Ok(())
        }
    }
}
