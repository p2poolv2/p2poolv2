// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod calc;
pub mod payout;
pub mod stats;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPair {
    pub address: bitcoin::Address,
    pub amount: bitcoin::Amount,
}
