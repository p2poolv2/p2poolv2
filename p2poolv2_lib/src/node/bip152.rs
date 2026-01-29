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

/*!
 * BIP-152-like implementation
 */

use bitcoin::{
    bip152::{BlockTransactionsRequest, HeaderAndShortIds, PrefilledTransaction, ShortId},
    consensus::Encodable,
};

/// Similar to [HeaderAndShortIds] but with added data for the sharechain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareHeaderAndShortIds {
    bitcoin_header: HeaderAndShortIds,
    ///  The short transaction IDs calculated from the transactions
    ///  which were not provided explicitly in sharechain_prefilled_txs.
    sharechain_short_ids: Vec<ShortId>,
    ///  Used to provide the coinbase transaction and a select few
    ///  which we expect a peer may be missing.
    sharechain_prefilled_txs: Vec<PrefilledTransaction>,
}

/// Similar to [BlockTransactionsRequest] but with the added index for sharechain transactions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareBlockTransactionsRequest {
    /// Bitcoin transactions from the [ShareBlock]
    bitcoin_indexes: Vec<u64>,
    block_txns: BlockTransactionsRequest,
}

impl ShareBlockTransactionsRequest {
    pub fn new(bitcoin_indexes: Vec<u64>, block_txns: BlockTransactionsRequest) -> Self {
        ShareBlockTransactionsRequest {
            bitcoin_indexes,
            block_txns,
        }
    }
}

impl Encodable for ShareBlockTransactionsRequest {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        // See how we are going to implement Run Length Encoding for both indexes
        todo!()
    }
}

#[repr(i8)]
#[derive(Debug, Clone)]
pub enum CompactBlockRelay {
    /// Disabled when the other node can't handle it
    Disabled = -1,
    /// **Low** bandwidth connection
    LowBandwidth = 0,
    /// **High** bandwidth connection
    HighBandwidth = 1,
}
