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

use super::{Accounting, AccountingShare};
use stratum::work::coinbase::OutputPair;

pub struct SimplePPLNS<T> {
    /// PPLNS window is the number of blocks the total work for the PPLNS window should stretch to.
    window_size: usize,

    /// Shares submitted by miners and possibly received from peers.
    shares: Vec<T>,
}

pub struct SimplePPLNSShare {
    work: bitcoin::Work,
    miner_btcaddress: bitcoin::Address,
}

impl SimplePPLNSShare {
    pub fn new(work: bitcoin::Work, miner_btcaddress: bitcoin::Address) -> Self {
        SimplePPLNSShare {
            work,
            miner_btcaddress,
        }
    }
}

impl AccountingShare for SimplePPLNSShare {
    fn get_work(&self) -> bitcoin::Work {
        self.work
    }

    fn get_miner_btcaddress(&self) -> bitcoin::Address {
        self.miner_btcaddress.clone()
    }
}

impl<T> Accounting<T> for SimplePPLNS<T>
where
    T: AccountingShare,
{
    fn add_share(&mut self, value: T) {
        self.shares.push(value);
    }

    fn get_payout_distribution(&self, total_work: bitcoin::Work) -> Vec<OutputPair> {
        // Implementation of payout distribution logic
        vec![]
    }

    fn get_shares_for_work(&self, total_work: bitcoin::Work) -> Vec<&T> {
        // Implementation to get shares for the given amount of work
        vec![]
    }
}
