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

use bitcoin::consensus::{Decodable, Encodable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxMetadata {
    pub txid: bitcoin::Txid,
    pub version: bitcoin::transaction::Version,
    pub lock_time: bitcoin::absolute::LockTime,
    pub input_count: u32,
    pub output_count: u32,
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

        Ok(TxMetadata {
            txid,
            version,
            lock_time,
            input_count,
            output_count,
        })
    }
}

/// ShareBlock metadata capturing if a share is valid and confirmed
/// This is stored indexed by the blockhash, we can later optimise to internal key, if needed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockMetadata {
    pub height: Option<u32>,
    pub is_valid: bool,
    pub is_confirmed: bool,
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

        Ok(BlockMetadata {
            height,
            is_valid,
            is_confirmed,
        })
    }
}
