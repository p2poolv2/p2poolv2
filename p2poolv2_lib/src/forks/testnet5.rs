// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fork activation heights for testnet5.

use super::ForkSchedule;

pub(super) const SCHEDULE: ForkSchedule = ForkSchedule {
    capped_coinbase_height: Some(60_000),
};
