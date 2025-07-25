use crate::bitcoin::utils::Utxo;
use log::{info, error};
use thiserror::Error;

/// Errors that can occur while validating HTLC UTXOs.
#[derive(Error, Debug)]
pub enum HtlcValidationError {
    #[error("UTXO is unconfirmed")]
    UnconfirmedUtxo,
    #[error("UTXO has insufficient confirmations: {current} < {required}")]
    InsufficientConfirmations { current: u32, required: u32 },
    #[error("UTXO is outside the swap window: expired at {expiry_height}, current height {current_height}")]
    SwapWindowExpired { expiry_height: u32, current_height: u32 },
}

/// Errors that can occur while checking refundable UTXOs.
#[derive(Error, Debug)]
pub enum RefundValidationError {
    #[error("UTXO is not yet refundable: refund at {refund_height}, current block {current_height}")]
    NotYetRefundable { refund_height: u32, current_height: u32 },
}

/// Checks if a UTXO is confirmed with required confirmations
/// and still within the claimable swap window.
pub fn is_valid_htlc_utxo(
    utxo: &Utxo,
    confirmation_threshold: u32,
    timelock: u32,
    min_buffer_blocks: u32,
    current_block_height: u32,
) -> Result<(bool, Option<u32>), HtlcValidationError> {
    // 1️⃣ Check if UTXO is confirmed and has enough confirmations
    if !utxo.status.confirmed {
        info!("UTXO is unconfirmed.");
        return Err(HtlcValidationError::UnconfirmedUtxo);
    }

    let confirmations = current_block_height.saturating_sub(utxo.status.block_height);
    if confirmations < confirmation_threshold {
        info!(
            "UTXO has {} confirmations, requires minimum {}.",
            confirmations, confirmation_threshold
        );
        return Err(HtlcValidationError::InsufficientConfirmations {
            current: confirmations,
            required: confirmation_threshold,
        });
    }

    // 2️⃣ Check if still within the swap claim window
    let expiry_height = utxo.status.block_height + timelock;
    if expiry_height.saturating_sub(min_buffer_blocks) <= current_block_height {
        info!(
            "UTXO is outside the swap window. Expired at {}, current height {}.",
            expiry_height, current_block_height
        );
        return Err(HtlcValidationError::SwapWindowExpired {
            expiry_height,
            current_height: current_block_height,
        });
    }

    info!(
        "UTXO is within the swap window. Expires at block {}.",
        expiry_height
    );

    let swap_window = expiry_height.saturating_sub(current_block_height);
    Ok((true, Some(swap_window)))
}

/// Checks if a given UTXO is eligible for refund based on timelock expiry.
pub fn is_utxo_refundable(
    utxo_block_height: u32,
    timelock: u32,
    current_block_height: u32,
) -> Result<bool, RefundValidationError> {
    let refund_height = utxo_block_height + timelock;

    if current_block_height < refund_height {
        info!(
            "UTXO is not yet refundable. Refund at block {}, current block {}.",
            refund_height, current_block_height
        );
        return Err(RefundValidationError::NotYetRefundable {
            refund_height,
            current_height: current_block_height,
        });
    }

    info!(
        "UTXO is in refund window. Refund allowed since block {}, current block {}.",
        refund_height, current_block_height
    );
    Ok(true)
}

/// Filters UTXOs that are eligible for redeem based on the timelock.
pub fn filter_valid_htlc_utxos(
    utxos: Vec<&Utxo>,
    confirmation_threshold: u32,
    timelock: u32,
    min_buffer_blocks: u32,
    current_block_height: u32,
) -> (Vec<&Utxo>, u32, u64) {
    let mut valid_utxos = Vec::new();
    let mut min_swap_window = timelock;
    let mut total_sats: u64 = 0;

    for utxo in utxos {
        match is_valid_htlc_utxo(
            utxo,
            confirmation_threshold,
            timelock,
            min_buffer_blocks,
            current_block_height,
        ) {
            Ok((is_valid, swap_window_opt)) => {
                if is_valid {
                    total_sats += utxo.value;
                    valid_utxos.push(utxo);
                    if let Some(window) = swap_window_opt {
                        if window < min_swap_window {
                            min_swap_window = window;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to validate UTXO: {}", e);
            }
        }
    }

    (valid_utxos, min_swap_window, total_sats)
}

/// Filters UTXOs that are eligible for refund based on the timelock.
pub fn filter_refundable_utxos(
    utxos: Vec<&Utxo>,
    timelock: u32,
    current_block_height: u32,
) -> Vec<&Utxo> {
    utxos
        .into_iter()
        .filter(|utxo| {
            is_utxo_refundable(utxo.status.block_height, timelock, current_block_height)
                .map_err(|e| {
                    error!("Failed to check refundable UTXO: {}", e);
                    e
                })
                .is_ok()
        })
        .collect()
}