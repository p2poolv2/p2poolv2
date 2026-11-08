// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `blockchain.*` methods, one module per Electrum namespace. They read
//! the share chain, and `dispatch` gates them on sync.

pub(crate) mod block;
mod script;
pub(crate) mod scripthash;
pub(crate) mod transaction;
