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

/// Validation status of a share, independent of which chain it is on
/// (see [`ChainMembership`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Status {
    /// Not yet validated
    Pending = 0,
    /// PoW / header validated, but not chain-context (coinbase/payout) validated
    HeaderValid = 1,
    /// Validation failed
    Invalid = 2,
    /// Fully validated, including chain-context checks (coinbase/payout, uncles).
    BlockValid = 3,
}

impl Encodable for Status {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        (*self as u8).consensus_encode(w)
    }
}

impl Decodable for Status {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let value = u8::consensus_decode(r)?;
        match value {
            0 => Ok(Status::Pending),
            1 => Ok(Status::HeaderValid),
            2 => Ok(Status::Invalid),
            3 => Ok(Status::BlockValid),
            _ => Err(bitcoin::consensus::encode::Error::ParseFailed(
                "Invalid Status value",
            )),
        }
    }
}

/// Identify which chain a share currently sits on.
///
/// This is independent of validation `Status`: a share can be on the
/// candidate chain while still only `HeaderValid`, and a share that failed
/// validation or was reorged out is `None` (off any chain) while its `Status`
/// records why. Keeping chain membership separate from validation lets us
/// mark a candidate `Invalid` without losing track of the candidate chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ChainMembership {
    /// Not on the candidate or confirmed chain.
    None = 0,
    /// On the candidate (best-work header) chain.
    Candidate = 1,
    /// On the confirmed chain.
    Confirmed = 2,
}

impl Encodable for ChainMembership {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        (*self as u8).consensus_encode(w)
    }
}

impl Decodable for ChainMembership {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let value = u8::consensus_decode(r)?;
        match value {
            0 => Ok(ChainMembership::None),
            1 => Ok(ChainMembership::Candidate),
            2 => Ok(ChainMembership::Confirmed),
            _ => Err(bitcoin::consensus::encode::Error::ParseFailed(
                "Invalid ChainMembership value",
            )),
        }
    }
}

/// ShareBlock metadata capturing the expected height and the chain
/// work for the block. These values are computed when the block is
/// received based on the height and chain work of the previous
/// blockhash.
///
/// This is stored indexed by the blockhash, we can later optimise to
/// internal key, if needed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockMetadata {
    /// Expected height of the block based on the expected height of previous blockhash
    pub expected_height: Option<u32>,
    /// Total chain work up to the share block
    pub chain_work: Work,
    /// Share validation status (independent of chain membership).
    pub status: Status,
    /// The chain that the share is on (independent of validation status).
    pub chain: ChainMembership,
}

impl Encodable for BlockMetadata {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;

        // Encode Option<u32> for height
        match &self.expected_height {
            Some(h) => {
                len += true.consensus_encode(w)?;
                len += h.consensus_encode(w)?;
            }
            None => {
                len += false.consensus_encode(w)?;
            }
        }

        len += self.chain_work.to_le_bytes().consensus_encode(w)?;
        len += self.status.consensus_encode(w)?;
        len += self.chain.consensus_encode(w)?;
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

        let chain_work = Work::from_le_bytes(<[u8; 32]>::consensus_decode(r)?);
        let status = Status::consensus_decode(r)?;
        let chain = ChainMembership::consensus_decode(r)?;

        Ok(BlockMetadata {
            expected_height: height,
            chain_work,
            status,
            chain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::{self, encode};

    #[test]
    fn test_block_metadata_roundtrip_preserves_chain() {
        for (status, chain) in [
            (Status::HeaderValid, ChainMembership::None),
            (Status::HeaderValid, ChainMembership::Candidate),
            (Status::BlockValid, ChainMembership::Confirmed),
            (Status::Invalid, ChainMembership::None),
        ] {
            let metadata = BlockMetadata {
                expected_height: Some(42),
                chain_work: Work::from_le_bytes([7u8; 32]),
                status,
                chain,
            };
            let bytes = consensus::serialize(&metadata);
            let decoded: BlockMetadata = encode::deserialize(&bytes).unwrap();
            assert_eq!(decoded, metadata);
            assert_eq!(decoded.chain, chain);
        }
    }

    #[test]
    fn test_chain_membership_roundtrip() {
        for chain in [
            ChainMembership::None,
            ChainMembership::Candidate,
            ChainMembership::Confirmed,
        ] {
            let bytes = consensus::serialize(&chain);
            let decoded: ChainMembership = encode::deserialize(&bytes).unwrap();
            assert_eq!(decoded, chain);
        }
    }
}
