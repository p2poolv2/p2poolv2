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

use crate::node::messages::Message;
use std::error::Error;
use tokio::sync::oneshot;

/// Struct for queruying the PPLNS shares from the node
#[derive(Debug, Clone)]
pub struct GetPplnsShareQuery {
    /// Maximum number of shares to return
    pub limit: usize,
    /// Optional start time (unix timestamp in seconds) to filter shares
    pub start_time: Option<u64>,
    /// Optional end time (unix timestamp in seconds) to filter shares
    pub end_time: Option<u64>,
}

/// Commands for communication between node handle and actor
/// We allow large enum variants because we want to avoid heap allocations for these frequently used messages
/// We know that the size difference is large, and we are willing to accept it
#[derive(Debug)]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Command telling node's event loop to send message to a specific peer
    SendToPeer(
        libp2p::PeerId,
        Message,
        oneshot::Sender<Result<(), Box<dyn Error + Send + Sync>>>,
    ),
    /// Command to get a list of connected peers
    GetPeers(oneshot::Sender<Vec<libp2p::PeerId>>),
    /// Command to shutdown node
    Shutdown(oneshot::Sender<()>),
    /// Get PPLNS shares from the node with optional filtering
    GetPplnsShares(
        GetPplnsShareQuery,
        oneshot::Sender<Vec<p2poolv2_accounting::simple_pplns::SimplePplnsShare>>,
    ),
}
