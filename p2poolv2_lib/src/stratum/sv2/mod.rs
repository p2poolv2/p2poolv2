// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stratum V2 Job Declaration for a local miner.
//!
//! The frames and messages are the published Stratum V2 types. Configuring an
//! external authority key enables authenticated Noise. Without one, connections
//! use the unencrypted framing allowed between local roles.
//!
//! A Mining connection can also open standard and extended channels: every
//! template becomes a job per channel, and submitted shares go through the
//! same block submission and share-chain emission as SV1 (see `mining`).
//!
//! `SetupConnection` flag bit 0 (`DECLARE_TX_DATA`) selects the mode.
//! Set, the client uses Full-Template: `DeclareMiningJob` plus
//! `ProvideMissingTransactions`. Clear, the client uses Coinbase-only:
//! `DeclareMiningJob` is rejected and the client keeps its transactions private.
//! BCH extended channels negotiate work selection and install declared jobs only
//! after validating the token, header, coinbase and exact share-chain payouts.
//! Full templates also require a successful local BCHN proposal check.
//!
//! The node can also be a Template Distribution client: with
//! `template_source = "sv2"` its templates come from a Stratum V2 Template
//! Provider and its blocks go back there (see `template_distribution`).

mod custom_job;
#[cfg(all(test, not(feature = "sim")))]
mod live_tests;
mod mining;
mod noise;
mod server;
mod session;
mod template_distribution;

pub use mining::EXTRANONCE_SIZE;
#[cfg(test)]
pub(crate) use noise::NoiseTransport;
pub use server::bind;
pub(crate) use server::{Sv2Mining, serve};
#[cfg(test)]
pub(crate) use session::{Declaration, DeclaredJob, decode_plain_frames, encode_message};
pub use session::{JobDeclarationMode, JobRegistry, PoolTransactionCache, Sv2Connection};
pub use template_distribution::{ProvidedTemplate, start_template_provider};

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
