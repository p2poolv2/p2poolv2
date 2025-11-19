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

use bitcoin::Work;
use bitcoin::consensus::{Decodable, Encodable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxMetadata {
    pub txid: bitcoin::Txid,
    pub version: bitcoin::transaction::Version,
    pub lock_time: bitcoin::absolute::LockTime,
    pub input_count: u32,
    pub output_count: u32,
    /// Transaction has been validated - all input scripts are valid, is not double spending etc.
    pub validated: bool,
}

impl Encodable for TxMetadata {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.txid.consensus_encode(w)?;
        len += self.version.consensus_encode(w)?;
        len += self.lock_time.consensus_encode(w)?;
        len += self.input_count.consensus_encode(w)?;
        len += self.output_count.consensus_encode(w)?;
        len += self.validated.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for TxMetadata {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let txid = bitcoin::Txid::consensus_decode(r)?;
        let version = bitcoin::transaction::Version::consensus_decode(r)?;
        let lock_time = bitcoin::absolute::LockTime::consensus_decode(r)?;
        let input_count = u32::consensus_decode(r)?;
        let output_count = u32::consensus_decode(r)?;
        let validated = bool::consensus_decode(r)?;

        Ok(TxMetadata {
            txid,
            version,
            lock_time,
            input_count,
            output_count,
            validated,
        })
    }
}

/// ShareBlock metadata capturing if a share is valid and confirmed
/// This is stored indexed by the blockhash, we can later optimise to internal key, if needed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockMetadata {
    /// Height of the block, this is also tracked in BlockHeight index
    pub height: Option<u32>,
    /// Validation status of the block in the share chain
    pub is_valid: bool,
    /// Confirmation status of the block in the share chain
    pub is_confirmed: bool,
    /// Total chain work up to the share block
    pub chain_work: Work,
}

impl Encodable for BlockMetadata {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;

        // Encode Option<u32> for height
        match &self.height {
            Some(h) => {
                len += true.consensus_encode(w)?;
                len += h.consensus_encode(w)?;
            }
            None => {
                len += false.consensus_encode(w)?;
            }
        }

        len += self.is_valid.consensus_encode(w)?;
        len += self.is_confirmed.consensus_encode(w)?;
        len += self.chain_work.to_le_bytes().consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for BlockMetadata {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        // Decode Option<u32>
        let height = if bool::consensus_decode(r)? {
            Some(u32::consensus_decode(r)?)
        } else {
            None
        };

        let is_valid = bool::consensus_decode(r)?;
        let is_confirmed = bool::consensus_decode(r)?;
        let chain_work = Work::from_le_bytes(<[u8; 32]>::consensus_decode(r)?);

        Ok(BlockMetadata {
            height,
            is_valid,
            is_confirmed,
            chain_work,
        })
    }
}
