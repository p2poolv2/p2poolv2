// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::accounting::payout::simple_pplns::SimplePplnsShare;
use crate::shares::coinbase_proof::CoinbaseProof;
use crate::shares::extranonce::Extranonce;
use crate::shares::share_commitment::ShareCommitment;
use crate::stratum::work::block_template::BlockTemplate;
use bitcoin::block::Header;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Shares emitted by stratum and consumed by accounting and p2p
/// network.
pub struct Emission {
    pub pplns: SimplePplnsShare,
    pub header: Header,
    pub blocktemplate: Arc<BlockTemplate>,
    pub share_commitment: Option<ShareCommitment>,
    /// Nanosecond timestamp embedded in the coinbase scriptSig.
    pub coinbase_nsecs: u64,
    /// Merkle branches for the template transactions (excluding coinbase).
    pub template_merkle_branches: Vec<bitcoin::TxMerkleNode>,
    /// Combined extranonce (enonce1 || enonce2) from the stratum submission.
    pub extranonce: Extranonce,
    /// Midstate proof of the commitment in the bitcoin coinbase, present
    /// exactly when `share_commitment` is: built where the full coinbase is
    /// still in hand, at submission.
    pub coinbase_proof: Option<CoinbaseProof>,
}

pub type EmissionSender = mpsc::Sender<Emission>;
pub type EmissionReceiver = mpsc::Receiver<Emission>;
