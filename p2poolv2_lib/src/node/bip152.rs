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
    consensus::{Decodable, Encodable},
};

use crate::shares::share_block::ShareHeader;

/// Similar to [HeaderAndShortIds] but with added data for the sharechain
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareHeaderAndShortIds {
    /// Bitcoin block header and short ids
    pub bitcoin_header: HeaderAndShortIds,
    /// ShareChain block header
    pub sharechain_header: ShareHeader,
    ///  The short transaction IDs calculated from the transactions
    ///  which were not provided explicitly in sharechain_prefilled_txs.
    pub sharechain_short_ids: Vec<ShortId>,
    ///  Used to provide the coinbase transaction and a select few
    ///  which we expect a peer may be missing.
    pub sharechain_prefilled_txs: Vec<PrefilledTransaction>,
}

/// Request for missing txs in compact share block (separate bitcoin/sharechain RLE indexes per BIP152)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareBlockTransactionsRequest {
    /// Bitcoin missing tx indexes (RLE encoded)
    pub bitcoin_req: BlockTransactionsRequest,
    /// Sharechain missing tx indexes (RLE encoded)
    pub sharechain_req: BlockTransactionsRequest,
}

impl ShareBlockTransactionsRequest {
    pub fn new(
        bitcoin_req: BlockTransactionsRequest,
        sharechain_req: BlockTransactionsRequest,
    ) -> Self {
        Self {
            bitcoin_req,
            sharechain_req,
        }
    }
}

impl Encodable for ShareBlockTransactionsRequest {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.sharechain_req.consensus_encode(writer)?;
        len += self.bitcoin_req.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for ShareBlockTransactionsRequest {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let sharechain_req = BlockTransactionsRequest::consensus_decode(r)?;
        let bitcoin_req = BlockTransactionsRequest::consensus_decode(r)?;
        Ok(Self {
            bitcoin_req,
            sharechain_req,
        })
    }
}

impl Encodable for ShareHeaderAndShortIds {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.bitcoin_header.consensus_encode(writer)?;
        len += bitcoin::VarInt(self.sharechain_short_ids.len() as u64).consensus_encode(writer)?;
        for short_id in &self.sharechain_short_ids {
            len += short_id.consensus_encode(writer)?;
        }
        len +=
            bitcoin::VarInt(self.sharechain_prefilled_txs.len() as u64).consensus_encode(writer)?;
        for ptx in &self.sharechain_prefilled_txs {
            len += ptx.consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl Decodable for ShareHeaderAndShortIds {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let bitcoin_header = HeaderAndShortIds::consensus_decode(r)?;
        let sharechain_header = ShareHeader::consensus_decode(r)?;
        let sharechain_short_ids_len = bitcoin::VarInt::consensus_decode(r)?.0 as usize;
        let mut sharechain_short_ids = Vec::with_capacity(sharechain_short_ids_len);
        for _ in 0..sharechain_short_ids_len {
            sharechain_short_ids.push(ShortId::consensus_decode(r)?);
        }
        let sharechain_prefilled_txs_len = bitcoin::VarInt::consensus_decode(r)?.0 as usize;
        let mut sharechain_prefilled_txs = Vec::with_capacity(sharechain_prefilled_txs_len);
        for _ in 0..sharechain_prefilled_txs_len {
            sharechain_prefilled_txs.push(PrefilledTransaction::consensus_decode(r)?);
        }
        Ok(Self {
            bitcoin_header,
            sharechain_header,
            sharechain_short_ids,
            sharechain_prefilled_txs,
        })
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
