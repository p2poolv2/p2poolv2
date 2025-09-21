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

//! Test utilities for p2poolv2_accounting

#[cfg(any(test, feature = "test-utils"))]
use crate::simple_pplns::{SimplePplnsShare, payout::PplnsShareProvider};
#[cfg(any(test, feature = "test-utils"))]
use std::error::Error;

/// Mock implementation of PplnsShareProvider for testing
#[cfg(any(test, feature = "test-utils"))]
#[derive(Clone)]
pub struct MockPplnsShareProvider {
    shares: Vec<SimplePplnsShare>,
}

#[cfg(any(test, feature = "test-utils"))]
impl MockPplnsShareProvider {
    pub fn new(shares: Vec<SimplePplnsShare>) -> Self {
        Self { shares }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl PplnsShareProvider for MockPplnsShareProvider {
    fn get_pplns_shares_filtered(
        &self,
        _limit: usize,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> impl std::future::Future<
        Output = Result<Vec<SimplePplnsShare>, Box<dyn Error + Send + Sync>>,
    > + Send
    + '_ {
        async move {
            let filtered_shares: Vec<SimplePplnsShare> = self
                .shares
                .iter()
                .filter(|share| {
                    let timestamp_secs = share.timestamp / 1_000_000;
                    let after_start = start_time.is_none_or(|start| timestamp_secs >= start);
                    let before_end = end_time.is_none_or(|end| timestamp_secs <= end);
                    after_start && before_end
                })
                .cloned()
                .collect();

            // Return shares ordered by timestamp (oldest first, so .rev() in function makes them newest first)
            let mut result = filtered_shares;
            result.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            Ok(result)
        }
    }
}
