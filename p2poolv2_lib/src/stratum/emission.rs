// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

use crate::accounting::simple_pplns::SimplePplnsShare;
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
    pub coinbase: bitcoin::Transaction,
    pub blocktemplate: Arc<BlockTemplate>,
    pub share_commitment: Option<ShareCommitment>,
}

pub type EmissionSender = mpsc::Sender<Emission>;
pub type EmissionReceiver = mpsc::Receiver<Emission>;
