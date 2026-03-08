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

use crate::accounting::OutputPair;
use crate::config::StratumConfig;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use std::error::Error;

pub mod simple_pplns;

/// A trait for implementing a payout distribtuion
///
/// payout::simple_pplns implements this trait to provide a payout
/// distribtuion based on centralised PPLNS algorithm.
///
/// payout::share_chain_payout implments this trait from the share
/// chain data.
pub trait PayoutDistribution {
    fn get_output_distribution(
        &self,
        chain_store_handle: &ChainStoreHandle,
        total_difficulty: f64,
        total_amount: bitcoin::Amount,
        config: &StratumConfig<crate::config::Parsed>,
    ) -> Result<Vec<OutputPair>, Box<dyn Error + Send + Sync>>;
}
