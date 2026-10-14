// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stratum V2 Job Declaration for a local miner.
//!
//! The frames and messages are the published Stratum V2 types. A local
//! connection uses the unencrypted framing the specification allows between
//! local roles. This node does not generate a Noise static key.
//!
//! `SetupConnection` flag bit 0 (`DECLARE_TX_DATA`) selects the mode.
//! Set, the client uses Full-Template: `DeclareMiningJob` plus
//! `ProvideMissingTransactions`. Clear, the client uses Coinbase-only:
//! `DeclareMiningJob` is rejected and `SetCustomMiningJob` mines the pool
//! template. Either way the non-coinbase transactions are stored in CTOR.

mod server;
mod session;

pub use server::{bind, serve};
pub use session::{JobDeclarationMode, JobRegistry, PoolTransactionCache, Sv2Connection};

use bitcoin::Transaction;
use bitcoin::hashes::Hash;

/// Canonical transaction order: ascending display order of the txid.
///
/// Bitcoin Cash compares the transaction id the way it is shown, which is the
/// reverse of the internal hash bytes. The coinbase is not part of this list.
pub fn sort_ctor(transactions: &mut [Transaction]) {
    transactions.sort_by_key(ctor_key);
}

fn ctor_key(transaction: &Transaction) -> [u8; 32] {
    let mut key = transaction.compute_txid().to_byte_array();
    key.reverse();
    key
}
