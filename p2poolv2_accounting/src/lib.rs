// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

pub mod calc;
pub mod simple_pplns;
pub mod stats;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct OutputPair {
    pub address: bitcoin::Address,
    pub amount: bitcoin::Amount,
}

/// Trait for accounting shares in the system.
/// Different mining strategies will implement this trait differently.
pub trait AccountingShare {
    /// Get the difficulty done to mine the share.
    fn get_difficulty(&self) -> u64;

    /// Get btcaddress for the miner who is to be rewarded for the share.
    fn get_miner_btcaddress(&self) -> String;
}

/// Account trait for share accounting.
/// We provide implementations of a simple PPLNS accounting strategy.
pub trait Accounting<T>
where
    T: AccountingShare,
{
    /// Add share to accounting
    fn add_share(&mut self, value: T);

    /// Get payout distribution as per the accounting engine's logic
    /// The shares collected should add up to total_difficulty.
    fn get_payout_distribution(&self, total_difficulty: u64) -> Vec<OutputPair>;

    /// Get shares for the given amount of difficulty.
    fn get_shares_for_difficulty(&self, total_difficulty: u64) -> Vec<&T>;
}
