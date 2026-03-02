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

use crate::shares::share_block::{ShareBlock, ShareHeader, Txids};
use bitcoin::consensus::{Decodable, Encodable};

/// A variant of ShareBlock used for storage that excludes transactions
#[derive(Clone, PartialEq, Debug)]
pub struct StorageShareBlock {
    /// The header of the share block
    pub header: ShareHeader,
    /// List of txids. Full transactions are stored separately in transactions cf.
    pub txids: Txids,
    /// List of bitcoin transaction ids, bitcoin transactions are
    /// stored separately in bitcoin transactions cf.
    ///
    /// Different shares will include the same transactions. Avoiding
    /// duplicate storage of these transactions is important here.
    pub bitcoin_txids: Txids,
}

impl From<&ShareBlock> for StorageShareBlock {
    fn from(block: &ShareBlock) -> Self {
        Self {
            header: block.header.clone(),
            txids: Txids(
                block
                    .transactions
                    .iter()
                    .map(|tx| tx.compute_txid())
                    .collect(),
            ),
            bitcoin_txids: Txids(
                block
                    .bitcoin_transactions
                    .iter()
                    .map(|tx| tx.compute_txid())
                    .collect(),
            ),
        }
    }
}

impl Encodable for StorageShareBlock {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.header.consensus_encode(w)?;
        len += self.txids.consensus_encode(w)?;
        len += self.bitcoin_txids.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for StorageShareBlock {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(StorageShareBlock {
            header: ShareHeader::consensus_decode(r)?,
            txids: Txids::consensus_decode(r)?,
            bitcoin_txids: Txids::consensus_decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::StorageShareBlock;
    use crate::test_utils::TestShareBlockBuilder;

    #[test]
    fn test_storage_share_block_conversion() {
        let share = &TestShareBlockBuilder::new()
            .prev_share_blockhash(
                "0000000086704a35f17580d06f76d4c02d2b1f68774800675fb45f0411205bb4".into(),
            )
            .miner_pubkey("020202020202020202020202020202020202020202020202020202020202020202")
            .work(1)
            .build();

        // Test conversion to StorageShareBlock
        let storage_share: StorageShareBlock = share.into();

        // Verify header and miner_share are preserved
        assert_eq!(storage_share.header, share.header);
    }
}
