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

pub mod payout_distribution;
pub mod sharechain_pplns;
pub mod simple_pplns;

use crate::config::PoolMode;
use payout_distribution::PayoutDistribution;
use sharechain_pplns::pplns_window::PplnsWindow;
use std::sync::{Arc, RwLock};

/// Build the payout implementation and shared PPLNS window for the
/// given pool mode.
///
/// In P2Poolv2 mode the share chain PPLNS payout walks the confirmed
/// chain and the returned window is shared with the organise worker.
///
/// In Hydrapool mode the simple PPLNS payout reads shares directly
/// from rocksdb. The returned window is an empty placeholder that
/// satisfies the NodeHandle interface but is not used for payouts.
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
            let payout = simple_pplns::payout::Payout::new(86400);
            let window = Arc::new(RwLock::new(PplnsWindow::new(network)));
            (Box::new(payout), window)
        }
    }
}
