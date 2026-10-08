// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod candidates;
pub mod chain_info;
pub mod dag;
pub mod share;
pub mod share_headers;
pub mod shares;
pub mod transaction;

/// Maximum number of candidates and shares that can be requested in a single query.
pub(crate) const MAX_NUM_SHARES_IN_RESPONSE: u32 = 100;
