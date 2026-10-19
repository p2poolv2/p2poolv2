// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod payout_distribution;
pub mod sharechain_pplns;
pub mod simple_pplns;

use crate::config::{BitcoinCashNetwork, Chain, PoolMode};
use payout_distribution::PayoutDistribution;
use sharechain_pplns::pplns_window::PplnsWindow;
use std::sync::{Arc, RwLock};

const DEFAULT_SIMPLE_PPLNS_STEP_SIZE_SECONDS: u64 = 86_400;

/// Build the payout implementation and shared PPLNS window for the
/// given pool mode.
///
/// In P2Poolv2 mode the share chain PPLNS payout walks the confirmed
/// chain and the returned window is shared with the organise worker. The
/// window rule follows `chain` (see `PplnsWindow::for_chain`), so the notifier
/// and the validator, which share the window, size it the same way.
///
/// In Hydrapool mode the simple PPLNS payout reads shares directly
/// from rocksdb. The returned window is an empty placeholder that
/// satisfies the NodeHandle interface but is not used for simple
/// pplns payouts.
pub fn build_payout_for_mode(
    mode: PoolMode,
    network: bitcoin::Network,
    chain: Chain,
    bitcoin_cash_network: Option<BitcoinCashNetwork>,
) -> (Box<dyn PayoutDistribution + Send>, Arc<RwLock<PplnsWindow>>) {
    match mode {
        PoolMode::P2poolv2 => {
            let payout =
                sharechain_pplns::Payout::with_window(PplnsWindow::new(network).for_chain(chain));
            let window = payout.shared_pplns_window();
            (Box::new(payout), window)
        }
        PoolMode::Hydrapool => {
            let payout = simple_pplns::payout::Payout::new(
                DEFAULT_SIMPLE_PPLNS_STEP_SIZE_SECONDS,
                bitcoin_cash_network,
            );
            let window = Arc::new(RwLock::new(PplnsWindow::new(network).for_chain(chain)));
            (Box::new(payout), window)
        }
    }
}

/// The window from `build_payout_for_mode` when the payout reads it, for
/// read-only views of it such as the API's `/miner`.
///
/// `None` in Hydrapool mode: the window there is a placeholder its
/// time-window payout never reads, so a view of it would not be the payout.
pub fn payout_pplns_window(
    mode: PoolMode,
    window: &Arc<RwLock<PplnsWindow>>,
) -> Option<Arc<RwLock<PplnsWindow>>> {
    match mode {
        PoolMode::P2poolv2 => Some(Arc::clone(window)),
        PoolMode::Hydrapool => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payout_pplns_window_is_the_shared_window_in_p2poolv2_mode() {
        let (_payout, window) = build_payout_for_mode(
            PoolMode::P2poolv2,
            bitcoin::Network::Signet,
            Chain::Bitcoin,
            None,
        );

        let payout_window = payout_pplns_window(PoolMode::P2poolv2, &window).unwrap();

        assert!(Arc::ptr_eq(&payout_window, &window));
    }

    #[test]
    fn payout_pplns_window_is_none_in_hydrapool_mode() {
        let (_payout, window) = build_payout_for_mode(
            PoolMode::Hydrapool,
            bitcoin::Network::Signet,
            Chain::Bitcoin,
            None,
        );

        assert!(payout_pplns_window(PoolMode::Hydrapool, &window).is_none());
    }
}
