// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::shares::coinbase_proof::CoinbaseProof;
use crate::shares::share_commitment::ShareCommitment;
use crate::stratum::work::block_template::BlockTemplate;
use bitcoin::Transaction;
use bitcoin::block::Header;
use std::sync::Arc;
use tokio::sync::mpsc;

/// A share emitted by stratum for the share chain.
///
/// Only P2Poolv2 mode emits. Hydrapool PPLNS shares go to the PPLNS share
/// worker instead (`accounting::payout::simple_pplns::share_worker`).
pub struct Emission {
    pub header: Header,
    pub blocktemplate: Arc<BlockTemplate>,
    pub share_commitment: ShareCommitment,
    /// Merkle branches for the template transactions (excluding coinbase).
    pub template_merkle_branches: Vec<bitcoin::TxMerkleNode>,
    /// The bitcoin coinbase the miner hashed, rebuilt from the job and the
    /// submitted extranonce2. Carried in the share block, where it holds the
    /// aux flags, extranonce and nanosecond timestamp the header no longer
    /// does.
    pub bitcoin_coinbase: Transaction,
    /// Midstate proof of the commitment in the bitcoin coinbase, built where
    /// the full coinbase is still in hand, at submission.
    pub coinbase_proof: CoinbaseProof,
}

pub type EmissionSender = mpsc::Sender<Emission>;
pub type EmissionReceiver = mpsc::Receiver<Emission>;
