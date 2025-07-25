use crate::bitcoin::utils::Utxo;

/// Checks if a UTXO is confirmed with required confirmations
/// and still within the claimable swap window.
pub fn is_valid_htlc_utxo(
    utxo: &Utxo,
    confirmation_threshold: u32,
    timelock: u32,
    min_buffer_blocks: u32,
    current_block_height: u32,
) -> (bool, Option<u32>) {
    // 1️⃣ Check if UTXO is confirmed and has enough confirmations
    if utxo.status.confirmed {
        let confirmations = current_block_height.saturating_sub(utxo.status.block_height);
        if confirmations < confirmation_threshold {
            println!(
                "UTXO has {} confirmations, requires minimum {}.",
                confirmations, confirmation_threshold
            );
            return (false, None);
        }
    } else {
        println!("UTXO is unconfirmed.");
        return (false, None);
    }

    // 2️⃣ Check if still within the swap claim window
    let expiry_height = utxo.status.block_height + timelock;
    if expiry_height.saturating_sub(min_buffer_blocks) > current_block_height {
        println!(
            "UTXO is within the swap window. Expires at block {}.",
            expiry_height
        );
    } else {
        println!(
            "UTXO is outside the swap window. Expired at {}, current height {}.",
            expiry_height, current_block_height
        );
        return (false, None);
    }

    let swap_window = expiry_height.saturating_sub(current_block_height);
    (true, Some(swap_window))
}

/// Checks if a given UTXO is eligible for refund based on timelock expiry.
pub fn is_utxo_refundable(
    utxo_block_height: u32,
    timelock: u32,
    current_block_height: u32,
) -> bool {
    let refund_height = utxo_block_height + timelock;

    if current_block_height >= refund_height {
        println!(
            "UTXO is in refund window. Refund allowed since block {}, current block {}.",
            refund_height, current_block_height
        );
        true
    } else {
        println!(
            "UTXO is not yet refundable. Refund at block {}, current block {}.",
            refund_height, current_block_height
        );
        false
    }
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
        let (is_valid, swap_window_opt) = is_valid_htlc_utxo(
            utxo,
            confirmation_threshold,
            timelock,
            min_buffer_blocks,
            current_block_height,
        );

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
        .filter(|utxo| is_utxo_refundable(utxo.status.block_height, timelock, current_block_height))
        .collect()
}


