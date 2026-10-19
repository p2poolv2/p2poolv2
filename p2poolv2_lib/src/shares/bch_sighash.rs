// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Replay-protected signature digest for Bitcoin Cash share transactions.
//!
//! The preimage follows the Bitcoin Cash replay-protected sighash
//! specification (the 2017 `SIGHASH_FORKID` upgrade): version, hash of
//! prevouts, hash of sequences, the spent outpoint, the script code, the
//! spent amount, this input's sequence, hash of outputs, locktime, and the
//! sighash type with fork id 0 in its high 24 bits. ECDSA and Schnorr
//! signatures sign the same digest.
//!
//! Only the types every Bitcoin Cash wallet produces are accepted: `ALL`,
//! `NONE` or `SINGLE`, with `FORKID` set and optionally `ANYONECANPAY`.
//! `SIGHASH_UTXOS` (2023) adds a commitment to every spent output and is
//! rejected rather than hashed without it. Token-prefixed spent outputs never
//! reach this digest because the share interpreter only accepts plain P2PKH.

use bitcoin::Transaction;
use bitcoin::consensus::Encodable;
use bitcoin::consensus::encode::VarInt;
use bitcoin::hashes::{Hash, sha256d};

/// Sighash flag that selects this digest. Bitcoin Cash requires it.
pub const SIGHASH_FORKID: u8 = 0x40;
/// Sighash flag that commits to this input only.
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
/// Sighash flag that commits to every spent output (2023). Not supported here.
pub const SIGHASH_UTXOS: u8 = 0x20;
const SIGHASH_ALL: u8 = 1;
const SIGHASH_NONE: u8 = 2;
const SIGHASH_SINGLE: u8 = 3;
/// Fork id committed in the high 24 bits of the type. The 2017 upgrade fixes it at 0.
const FORK_ID: u32 = 0;

/// Why a Bitcoin Cash signature digest could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SighashError {
    /// The type does not set the fork-id flag, so it is a Bitcoin signature.
    #[error("sighash type {0:#04x} does not set SIGHASH_FORKID")]
    MissingForkId(u8),
    /// The type sets `SIGHASH_UTXOS`, which this digest does not commit to.
    #[error("sighash type {0:#04x} sets SIGHASH_UTXOS, which share transactions do not support")]
    UtxosUnsupported(u8),
    /// The type is not `ALL`, `NONE` or `SINGLE` once its flags are removed.
    #[error("sighash type {0:#04x} is not a defined Bitcoin Cash sighash type")]
    UndefinedType(u8),
    /// The input index is past the end of the transaction.
    #[error("input {0} is outside the transaction")]
    InputOutOfRange(usize),
}

/// A sighash type byte that passed the Bitcoin Cash strict-encoding rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SighashType(u8);

impl SighashType {
    /// Check the type byte appended to a signature.
    ///
    /// The fork-id flag must be set, `SIGHASH_UTXOS` must not be, and the
    /// remaining base type must be `ALL`, `NONE` or `SINGLE`.
    pub fn from_byte(byte: u8) -> Result<Self, SighashError> {
        if byte & SIGHASH_FORKID == 0 {
            return Err(SighashError::MissingForkId(byte));
        }
        if byte & SIGHASH_UTXOS != 0 {
            return Err(SighashError::UtxosUnsupported(byte));
        }
        let base_type = byte & !(SIGHASH_FORKID | SIGHASH_ANYONECANPAY);
        if !(SIGHASH_ALL..=SIGHASH_SINGLE).contains(&base_type) {
            return Err(SighashError::UndefinedType(byte));
        }
        Ok(Self(byte))
    }

    fn base_type(self) -> u8 {
        self.0 & !(SIGHASH_FORKID | SIGHASH_ANYONECANPAY)
    }

    fn anyone_can_pay(self) -> bool {
        self.0 & SIGHASH_ANYONECANPAY != 0
    }

    /// The four bytes the preimage ends with: the type plus the fork id.
    fn committed(self) -> u32 {
        (FORK_ID << 8) | u32::from(self.0)
    }
}

/// Double SHA256 of the replay-protected preimage for one input.
///
/// `script_code` is the spent output's script without a length prefix, and
/// `amount` is the spent output's value in satoshis.
pub fn signature_hash(
    transaction: &Transaction,
    input_index: usize,
    script_code: &[u8],
    amount: u64,
    sighash_type: SighashType,
) -> Result<[u8; 32], SighashError> {
    let input = transaction
        .input
        .get(input_index)
        .ok_or(SighashError::InputOutOfRange(input_index))?;
    let base_type = sighash_type.base_type();
    let anyone_can_pay = sighash_type.anyone_can_pay();

    let hash_prevouts = if anyone_can_pay {
        [0u8; 32]
    } else {
        hash_prevouts(transaction)
    };
    let hash_sequence =
        if anyone_can_pay || base_type == SIGHASH_SINGLE || base_type == SIGHASH_NONE {
            [0u8; 32]
        } else {
            hash_sequences(transaction)
        };
    let hash_outputs = if base_type != SIGHASH_SINGLE && base_type != SIGHASH_NONE {
        hash_outputs(transaction.output.iter())
    } else if base_type == SIGHASH_SINGLE && input_index < transaction.output.len() {
        hash_outputs(transaction.output[input_index..=input_index].iter())
    } else {
        [0u8; 32]
    };

    let mut preimage =
        Vec::with_capacity(4 + 32 + 32 + 36 + 9 + script_code.len() + 8 + 4 + 32 + 4 + 4);
    preimage.extend_from_slice(&transaction.version.0.to_le_bytes());
    preimage.extend_from_slice(&hash_prevouts);
    preimage.extend_from_slice(&hash_sequence);
    encode_into(&input.previous_output, &mut preimage);
    encode_into(&VarInt::from(script_code.len()), &mut preimage);
    preimage.extend_from_slice(script_code);
    preimage.extend_from_slice(&amount.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_consensus_u32().to_le_bytes());
    preimage.extend_from_slice(&hash_outputs);
    preimage.extend_from_slice(&transaction.lock_time.to_consensus_u32().to_le_bytes());
    preimage.extend_from_slice(&sighash_type.committed().to_le_bytes());
    Ok(sha256d::Hash::hash(&preimage).to_byte_array())
}

fn hash_prevouts(transaction: &Transaction) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(transaction.input.len() * 36);
    for input in &transaction.input {
        encode_into(&input.previous_output, &mut bytes);
    }
    sha256d::Hash::hash(&bytes).to_byte_array()
}

fn hash_sequences(transaction: &Transaction) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(transaction.input.len() * 4);
    for input in &transaction.input {
        bytes.extend_from_slice(&input.sequence.to_consensus_u32().to_le_bytes());
    }
    sha256d::Hash::hash(&bytes).to_byte_array()
}

fn hash_outputs<'a>(outputs: impl ExactSizeIterator<Item = &'a bitcoin::TxOut>) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(outputs.len() * 34);
    for output in outputs {
        encode_into(output, &mut bytes);
    }
    sha256d::Hash::hash(&bytes).to_byte_array()
}

/// Consensus-encode into an in-memory buffer, which cannot fail.
fn encode_into<T: Encodable>(value: &T, bytes: &mut Vec<u8>) {
    value
        .consensus_encode(bytes)
        .expect("encoding into a Vec does not fail");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_with_fork_id_is_accepted() {
        assert!(SighashType::from_byte(0x41).is_ok());
    }

    #[test]
    fn none_single_and_anyone_can_pay_with_fork_id_are_accepted() {
        assert!(SighashType::from_byte(0x42).is_ok());
        assert!(SighashType::from_byte(0x43).is_ok());
        assert!(SighashType::from_byte(0xc1).is_ok());
        assert!(SighashType::from_byte(0xc3).is_ok());
    }

    #[test]
    fn a_bitcoin_type_without_fork_id_is_rejected() {
        assert_eq!(
            SighashType::from_byte(0x01),
            Err(SighashError::MissingForkId(0x01))
        );
    }

    #[test]
    fn sighash_utxos_is_rejected() {
        assert_eq!(
            SighashType::from_byte(0x61),
            Err(SighashError::UtxosUnsupported(0x61))
        );
    }

    #[test]
    fn an_undefined_base_type_is_rejected() {
        assert_eq!(
            SighashType::from_byte(0x40),
            Err(SighashError::UndefinedType(0x40))
        );
        assert_eq!(
            SighashType::from_byte(0x44),
            Err(SighashError::UndefinedType(0x44))
        );
        assert_eq!(
            SighashType::from_byte(0x5f),
            Err(SighashError::UndefinedType(0x5f))
        );
    }

    #[test]
    fn an_input_past_the_end_is_rejected() {
        let transaction = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let sighash_type = SighashType::from_byte(0x41).unwrap();
        assert_eq!(
            signature_hash(&transaction, 0, &[], 0, sighash_type),
            Err(SighashError::InputOutOfRange(0))
        );
    }
}
