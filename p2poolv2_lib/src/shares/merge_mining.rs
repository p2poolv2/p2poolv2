// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! One AuxPoW commitment output in a Bitcoin Cash coinbase.
//!
//! The payload is the merged-mining commitment from the Bitcoin wiki
//! specification: magic `fabe6d6d`, a 32-byte aux merkle root, the tree size,
//! and the nonce. It sits in a single zero-value `OP_RETURN` output. A
//! reserved commitment (zero root, size 0, nonce 0) holds the output's place
//! when the miner has not declared an aux chain. Bitcoin coinbases omit it.

use bitcoin::consensus::Encodable;
use bitcoin::script::Builder;
use bitcoin::{Amount, ScriptBuf, TxOut};

/// Magic that opens an AuxPoW commitment: `0xfa 0xbe 'm' 'm'`.
pub const AUXPOW_MAGIC: [u8; 4] = [0xfa, 0xbe, 0x6d, 0x6d];

/// Bytes in the commitment payload: magic, root, size, nonce.
pub const AUXPOW_COMMITMENT_LENGTH: usize = 4 + 32 + 4 + 4;

/// Aux merkle root, tree size, and nonce committed by one coinbase output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeMiningCommitment {
    /// Merkle root of the aux chain hashes, in the byte order AuxPoW stores.
    pub merkle_root: [u8; 32],
    /// Number of aux chains in the tree.
    pub tree_size: u32,
    /// Slot of this chain in the tree.
    pub nonce: u32,
}

impl MergeMiningCommitment {
    /// Commitment that reserves the output and names no aux chain.
    pub fn reserved() -> Self {
        Self {
            merkle_root: [0u8; 32],
            tree_size: 0,
            nonce: 0,
        }
    }

    /// The 44 bytes pushed by the commitment output.
    pub fn payload(self) -> [u8; AUXPOW_COMMITMENT_LENGTH] {
        let mut payload = [0u8; AUXPOW_COMMITMENT_LENGTH];
        payload[..4].copy_from_slice(&AUXPOW_MAGIC);
        payload[4..36].copy_from_slice(&self.merkle_root);
        payload[36..40].copy_from_slice(&self.tree_size.to_le_bytes());
        payload[40..44].copy_from_slice(&self.nonce.to_le_bytes());
        payload
    }

    /// Zero-value output carrying [`Self::payload`].
    pub fn output(self) -> TxOut {
        TxOut {
            value: Amount::ZERO,
            script_pubkey: commitment_script(self.payload()),
        }
    }

    /// Consensus encoding of [`Self::output`], for a Job Declaration token.
    pub fn output_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        self.output()
            .consensus_encode(&mut bytes)
            .expect("a vector writer does not fail");
        bytes
    }
}

fn commitment_script(payload: [u8; AUXPOW_COMMITMENT_LENGTH]) -> ScriptBuf {
    Builder::new()
        .push_opcode(bitcoin::opcodes::all::OP_RETURN)
        .push_slice(payload)
        .into_script()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_commitment_is_the_published_auxpow_layout() {
        let output = MergeMiningCommitment::reserved().output();
        let script = output.script_pubkey.as_bytes();
        assert_eq!(output.value, Amount::ZERO);
        assert_eq!(script[0], 0x6a);
        assert_eq!(script[1], AUXPOW_COMMITMENT_LENGTH as u8);
        assert_eq!(&script[2..6], &AUXPOW_MAGIC);
        assert_eq!(&script[6..38], &[0u8; 32]);
        assert_eq!(&script[38..42], &0u32.to_le_bytes());
        assert_eq!(&script[42..46], &0u32.to_le_bytes());
        assert_eq!(script.len(), 46);
    }
}
