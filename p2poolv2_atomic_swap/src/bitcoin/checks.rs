use crate::bitcoin::utils::Utxo;
use log::{error, info};
use thiserror::Error;

/// Errors that can occur while validating HTLC UTXOs.
#[derive(Error, Debug, PartialEq)]
pub enum HtlcValidationError {
    #[error("UTXO is unconfirmed")]
    UnconfirmedUtxo,
    #[error("UTXO has insufficient confirmations: {current} < {required}")]
    InsufficientConfirmations { current: u32, required: u32 },
    #[error("UTXO is outside the swap window: expired at {expiry_height}, current height {current_height}")]
    SwapWindowExpired {
        expiry_height: u32,
        current_height: u32,
    },
}

/// Errors that can occur while checking refundable UTXOs.
#[derive(Error, Debug, PartialEq)]
pub enum RefundValidationError {
    #[error(
        "UTXO is not yet refundable: refund at {refund_height}, current block {current_height}"
    )]
    NotYetRefundable {
        refund_height: u32,
        current_height: u32,
    },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin::utils::{Utxo, UtxoStatus};
    use env_logger;
    use log::info;

    // Helper to create a Utxo
    fn create_utxo(confirmed: bool, block_height: u32, value: u64) -> Utxo {
        Utxo {
            txid: "00".repeat(32), // 64-char hex string (32 bytes)
            vout: 0,
            value,
            status: UtxoStatus {
                confirmed,
                block_height,
                block_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                block_time: 1234567890,
            },
        }
    }

    #[test]
    fn test_is_valid_htlc_utxo() {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .try_init();

        let confirmation_threshold = 3;
        let timelock = 10;
        let min_buffer_blocks = 2;
        let current_block_height = 100;

        // Test 1: Unconfirmed UTXO
        let utxo_unconfirmed = create_utxo(false, 95, 10000);
        let result = is_valid_htlc_utxo(
            &utxo_unconfirmed,
            confirmation_threshold,
            timelock,
            min_buffer_blocks,
            current_block_height,
        );
        assert_eq!(result, Err(HtlcValidationError::UnconfirmedUtxo));
        info!("Tested unconfirmed UTXO");

        // Test 2: Insufficient confirmations
        let utxo_insufficient = create_utxo(true, 98, 10000);
        let result = is_valid_htlc_utxo(
            &utxo_insufficient,
            confirmation_threshold,
            timelock,
            min_buffer_blocks,
            current_block_height,
        );
        assert_eq!(
            result,
            Err(HtlcValidationError::InsufficientConfirmations {
                current: 2,
                required: 3
            })
        );
        info!("Tested insufficient confirmations");

        // Test 3: Expired swap window
        let utxo_expired = create_utxo(true, 88, 10000);
        let result = is_valid_htlc_utxo(
            &utxo_expired,
            confirmation_threshold,
            timelock,
            min_buffer_blocks,
            current_block_height,
        );
        assert_eq!(
            result,
            Err(HtlcValidationError::SwapWindowExpired {
                expiry_height: 98,
                current_height: 100
            })
        );
        info!("Tested expired swap window");

        // Test 4: Valid UTXO
        let utxo_valid = create_utxo(true, 93, 10000); // 93 + 10 - 2 = 101 > 100
        let result = is_valid_htlc_utxo(
            &utxo_valid,
            confirmation_threshold,
            timelock,
            min_buffer_blocks,
            current_block_height,
        );
        assert_eq!(
            result,
            Ok((true, Some(3))), // swap_window = 103 - 100 = 3
            "Expected valid UTXO with swap window of 3 blocks"
        );
        info!("Tested valid UTXO");
    }

    #[test]
    fn test_is_utxo_refundable() {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .try_init();

        let timelock = 10;
        let current_block_height = 100;

        // Test 1: Non-refundable UTXO
        let result = is_utxo_refundable(95, timelock, current_block_height);
        assert_eq!(
            result,
            Err(RefundValidationError::NotYetRefundable {
                refund_height: 105,
                current_height: 100
            })
        );
        info!("Tested non-refundable UTXO");

        // Test 2: Refundable UTXO
        let result = is_utxo_refundable(90, timelock, current_block_height);
        assert_eq!(result, Ok(true));
        info!("Tested refundable UTXO");
    }

    #[test]
    fn test_filter_valid_htlc_utxos() {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .try_init();

        let confirmation_threshold = 3;
        let timelock = 10;
        let min_buffer_blocks = 2;
        let current_block_height = 100;

        let utxos = vec![
            create_utxo(false, 95, 10000), // Unconfirmed
            create_utxo(true, 98, 15000),  // Insufficient confirmations
            create_utxo(true, 88, 20000),  // Expired (88 + 10 - 2 = 96 <= 100)
            create_utxo(true, 93, 25000),  // Valid (93 + 10 - 2 = 101 > 100)
            create_utxo(true, 94, 30000),  // Valid (94 + 10 - 2 = 102 > 100)
        ];

        let (valid_utxos, min_swap_window, total_sats) = filter_valid_htlc_utxos(
            utxos.iter().collect(),
            confirmation_threshold,
            timelock,
            min_buffer_blocks,
            current_block_height,
        );

        assert_eq!(valid_utxos.len(), 2, "Expected 2 valid UTXOs");
        assert_eq!(
            valid_utxos.iter().map(|u| u.value).collect::<Vec<u64>>(),
            vec![25000, 30000],
            "Expected valid UTXO values"
        );
        assert_eq!(min_swap_window, 3, "Expected min swap window of 3 blocks");
        assert_eq!(total_sats, 55000, "Expected total sats of 55000");
        info!("Tested filter_valid_htlc_utxos");
    }

    #[test]
    fn test_filter_refundable_utxos() {
        let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
            .try_init();

        let timelock = 10;
        let current_block_height = 100;

        let utxos = vec![
            create_utxo(true, 95, 10000), // Non-refundable (95 + 10 = 105 > 100)
            create_utxo(true, 90, 20000), // Refundable (90 + 10 = 100 <= 100)
            create_utxo(true, 85, 30000), // Refundable (85 + 10 = 95 <= 100)
        ];

        let refundable_utxos =
            filter_refundable_utxos(utxos.iter().collect(), timelock, current_block_height);

        assert_eq!(refundable_utxos.len(), 2, "Expected 2 refundable UTXOs");
        assert_eq!(
            refundable_utxos
                .iter()
                .map(|u| u.value)
                .collect::<Vec<u64>>(),
            vec![20000, 30000],
            "Expected refundable UTXO values"
        );
        info!("Tested filter_refundable_utxos");
    }
}
