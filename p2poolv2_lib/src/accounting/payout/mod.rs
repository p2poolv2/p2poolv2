// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod payout_distribution;
pub mod sharechain_pplns;
pub mod simple_pplns;

use crate::config::PoolMode;
use payout_distribution::PayoutDistribution;
use sharechain_pplns::pplns_window::PplnsWindow;
use std::sync::{Arc, RwLock};

const DEFAULT_SIMPLE_PPLNS_STEP_SIZE_SECONDS: u64 = 86_400;

/// Build the payout implementation and shared PPLNS window for the
/// given pool mode.
///
/// In P2Poolv2 mode the share chain PPLNS payout walks the confirmed
/// chain and the returned window is shared with the organise worker.
///
/// In Hydrapool mode the simple PPLNS payout reads shares directly
/// from rocksdb. The returned window is an empty placeholder that
/// satisfies the NodeHandle interface but is not used for simple
/// pplns payouts.
pub fn build_payout_for_mode(
    mode: PoolMode,
    network: bitcoin::Network,
) -> (Box<dyn PayoutDistribution + Send>, Arc<RwLock<PplnsWindow>>) {
    match mode {
        PoolMode::P2poolv2 => {
            let payout = sharechain_pplns::Payout::new(network);
            let window = payout.shared_pplns_window();
            (Box::new(payout), window)
        }
        PoolMode::Hydrapool => {
            let payout = simple_pplns::payout::Payout::new(DEFAULT_SIMPLE_PPLNS_STEP_SIZE_SECONDS);
            let window = Arc::new(RwLock::new(PplnsWindow::new(network)));
            (Box::new(payout), window)
        }
    }
}
