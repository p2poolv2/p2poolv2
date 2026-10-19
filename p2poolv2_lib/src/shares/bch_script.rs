// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bitcoin Cash script checks for share-chain transactions.
//!
//! A Bitcoin Cash share coinbase pays its owner's P2PKH script, so a share
//! transfer spends P2PKH outputs. This module accepts exactly that spend: a
//! 25-byte `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG` output
//! and a `<signature> <public key>` input of two direct pushes. Spending any
//! other output form (P2SH, multisig, token-prefixed outputs, the atomic-swap
//! scripts) is rejected, which is stricter than Bitcoin Cash and never looser.
//! The outputs a transfer creates are not restricted, as on Bitcoin, so a
//! share sent to any other script can never be spent on the share chain.
//!
//! Signature rules follow BCHN's standard script flags:
//!
//! - The sighash type must set `SIGHASH_FORKID` (see [`bch_sighash`]).
//! - A 64-byte signature body is a Bitcoin Cash Schnorr signature (2019
//!   upgrade). It is not BIP340: the challenge hashes the compressed public
//!   key, and the nonce point must have a quadratic-residue Y coordinate.
//! - Any other body is ECDSA in strict DER (BIP66) with a low S value.
//! - The public key is a compressed or uncompressed SEC1 key; hybrid keys
//!   are rejected.
//! - Inputs carry no witness, because Bitcoin Cash has no witness data.

use crate::shares::bch_sighash::{self, SighashError, SighashType};
use bitcoin::hashes::{Hash, hash160};
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::{Transaction, TxOut};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::{Group, PrimeField};
use k256::{AffinePoint, EncodedPoint, FieldBytes, FieldElement, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

const OP_DUP: u8 = 0x76;
const OP_HASH160: u8 = 0xa9;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xac;
const PUBKEY_HASH_LENGTH: u8 = 20;
const P2PKH_SCRIPT_LENGTH: usize = 25;
/// Largest push a single opcode byte can make. Larger pushes need
/// `OP_PUSHDATA`, which minimal-push rules forbid for signatures and keys.
const MAX_DIRECT_PUSH: u8 = 0x4b;
/// Length of a Bitcoin Cash Schnorr signature without its sighash byte.
const SCHNORR_SIGNATURE_LENGTH: usize = 64;
const COMPRESSED_KEY_LENGTH: usize = 33;
const UNCOMPRESSED_KEY_LENGTH: usize = 65;

/// Why a Bitcoin Cash share transaction failed its script checks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BchScriptError {
    /// The spent outputs are not one per input in input order.
    #[error("spent outputs do not match the transaction inputs")]
    SpentOutputsMismatch,
    /// An input carries witness data, which Bitcoin Cash does not have.
    #[error("input {input_index} carries witness data")]
    WitnessPresent { input_index: usize },
    /// The spent output or the input script is not the supported P2PKH spend.
    #[error("input {input_index} is not a <signature> <public key> spend of a P2PKH output")]
    UnsupportedScript { input_index: usize },
    /// The public key is not a compressed or uncompressed key on the curve.
    #[error("input {input_index} public key is not a valid compressed or uncompressed key")]
    InvalidPublicKey { input_index: usize },
    /// The public key does not hash to the spent output's key hash.
    #[error("input {input_index} public key does not match the P2PKH key hash")]
    PublicKeyHashMismatch { input_index: usize },
    /// The sighash type is not one Bitcoin Cash accepts here.
    #[error("input {input_index}: {source}")]
    Sighash {
        input_index: usize,
        source: SighashError,
    },
    /// The ECDSA signature is not strict DER.
    #[error("input {input_index} ECDSA signature is not strict DER")]
    NonStrictDer { input_index: usize },
    /// The ECDSA signature has an S value above half the group order.
    #[error("input {input_index} ECDSA signature has a high S value")]
    HighS { input_index: usize },
    /// The signature does not verify against the key and the digest.
    #[error("input {input_index} signature does not verify")]
    SignatureRejected { input_index: usize },
}

/// Check every input of a non-coinbase Bitcoin Cash share transaction.
///
/// `spent_outputs` holds one `(input_index, output)` pair per input, in
/// input order, as `ChainStoreHandle::get_all_prevouts` returns them.
pub fn verify_transaction(
    transaction: &Transaction,
    spent_outputs: &[(usize, TxOut)],
) -> Result<(), BchScriptError> {
    if spent_outputs.len() != transaction.input.len() {
        return Err(BchScriptError::SpentOutputsMismatch);
    }
    for (position, (input_index, spent_output)) in spent_outputs.iter().enumerate() {
        if *input_index != position {
            return Err(BchScriptError::SpentOutputsMismatch);
        }
        verify_input(transaction, position, spent_output)?;
    }
    Ok(())
}

/// Check one input against the output it spends.
fn verify_input(
    transaction: &Transaction,
    input_index: usize,
    spent_output: &TxOut,
) -> Result<(), BchScriptError> {
    let input = &transaction.input[input_index];
    if !input.witness.is_empty() {
        return Err(BchScriptError::WitnessPresent { input_index });
    }
    let script_pubkey = spent_output.script_pubkey.as_bytes();
    let pubkey_hash =
        p2pkh_hash(script_pubkey).ok_or(BchScriptError::UnsupportedScript { input_index })?;
    let (signature, public_key) = signature_and_key(input.script_sig.as_bytes())
        .ok_or(BchScriptError::UnsupportedScript { input_index })?;
    if !is_compressed_or_uncompressed(public_key) {
        return Err(BchScriptError::InvalidPublicKey { input_index });
    }
    if hash160::Hash::hash(public_key).as_byte_array() != pubkey_hash {
        return Err(BchScriptError::PublicKeyHashMismatch { input_index });
    }
    let (body, sighash_byte) = signature
        .split_last()
        .map(|(last, body)| (body, *last))
        .ok_or(BchScriptError::UnsupportedScript { input_index })?;
    let sighash_type =
        SighashType::from_byte(sighash_byte).map_err(|source| BchScriptError::Sighash {
            input_index,
            source,
        })?;
    let digest = bch_sighash::signature_hash(
        transaction,
        input_index,
        script_pubkey,
        spent_output.value.to_sat(),
        sighash_type,
    )
    .map_err(|source| BchScriptError::Sighash {
        input_index,
        source,
    })?;

    if body.len() == SCHNORR_SIGNATURE_LENGTH {
        verify_schnorr(body, public_key, &digest, input_index)
    } else {
        verify_ecdsa(body, public_key, &digest, input_index)
    }
}

/// The 20-byte key hash of a P2PKH script, or `None` for any other script.
fn p2pkh_hash(script: &[u8]) -> Option<&[u8; 20]> {
    if script.len() != P2PKH_SCRIPT_LENGTH
        || script[0] != OP_DUP
        || script[1] != OP_HASH160
        || script[2] != PUBKEY_HASH_LENGTH
        || script[23] != OP_EQUALVERIFY
        || script[24] != OP_CHECKSIG
    {
        return None;
    }
    script[3..23].try_into().ok()
}

/// Split an input script made of exactly two direct pushes.
fn signature_and_key(script_sig: &[u8]) -> Option<(&[u8], &[u8])> {
    let (signature, rest) = direct_push(script_sig)?;
    let (public_key, rest) = direct_push(rest)?;
    if rest.is_empty() {
        Some((signature, public_key))
    } else {
        None
    }
}

/// Read one push of 1 to 75 bytes made by its own length opcode.
fn direct_push(script: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&opcode, rest) = script.split_first()?;
    if opcode == 0 || opcode > MAX_DIRECT_PUSH {
        return None;
    }
    let length = usize::from(opcode);
    if rest.len() < length {
        return None;
    }
    Some(rest.split_at(length))
}

/// Bitcoin Cash strict encoding: 33 bytes starting 02 or 03, or 65 bytes
/// starting 04. Hybrid keys (06, 07) are rejected.
fn is_compressed_or_uncompressed(public_key: &[u8]) -> bool {
    match public_key.len() {
        COMPRESSED_KEY_LENGTH => public_key[0] == 0x02 || public_key[0] == 0x03,
        UNCOMPRESSED_KEY_LENGTH => public_key[0] == 0x04,
        _ => false,
    }
}

/// Verify a strict-DER, low-S ECDSA signature with libsecp256k1.
fn verify_ecdsa(
    der: &[u8],
    public_key: &[u8],
    digest: &[u8; 32],
    input_index: usize,
) -> Result<(), BchScriptError> {
    if !is_strict_der(der) {
        return Err(BchScriptError::NonStrictDer { input_index });
    }
    let signature = secp256k1::ecdsa::Signature::from_der(der)
        .map_err(|_| BchScriptError::NonStrictDer { input_index })?;
    let mut normalized = signature;
    normalized.normalize_s();
    if normalized != signature {
        return Err(BchScriptError::HighS { input_index });
    }
    let key = secp256k1::PublicKey::from_slice(public_key)
        .map_err(|_| BchScriptError::InvalidPublicKey { input_index })?;
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(*digest), &signature, &key)
        .map_err(|_| BchScriptError::SignatureRejected { input_index })
}

/// BIP66 strict DER for a signature body without its sighash byte.
///
/// The same checks as BCHN's `IsValidDERSignatureEncoding`: a compound of
/// two positive integers with no excess padding, 8 to 72 bytes in all.
fn is_strict_der(der: &[u8]) -> bool {
    let size = der.len();
    if !(8..=72).contains(&size) {
        return false;
    }
    if der[0] != 0x30 || usize::from(der[1]) != size - 2 {
        return false;
    }
    let r_length = usize::from(der[3]);
    if 5 + r_length >= size {
        return false;
    }
    let s_length = usize::from(der[5 + r_length]);
    if r_length + s_length + 6 != size {
        return false;
    }
    if der[2] != 0x02 || r_length == 0 || der[4] & 0x80 != 0 {
        return false;
    }
    if r_length > 1 && der[4] == 0x00 && der[5] & 0x80 == 0 {
        return false;
    }
    if der[r_length + 4] != 0x02 || s_length == 0 || der[r_length + 6] & 0x80 != 0 {
        return false;
    }
    if s_length > 1 && der[r_length + 6] == 0x00 && der[r_length + 7] & 0x80 == 0 {
        return false;
    }
    true
}

/// Verify a Bitcoin Cash Schnorr signature.
///
/// From the 2019-05-15 Schnorr specification: fail if `r >= p` or `s >= n`;
/// `e = SHA256(r || compressed(P) || m) mod n`; `R = sG - eP`; fail if `R` is
/// the point at infinity, if `x(R) != r`, or if `y(R)` is not a quadratic
/// residue modulo `p`.
fn verify_schnorr(
    signature: &[u8],
    public_key: &[u8],
    digest: &[u8; 32],
    input_index: usize,
) -> Result<(), BchScriptError> {
    let rejected = BchScriptError::SignatureRejected { input_index };
    let (r_bytes, s_bytes) = signature.split_at(32);
    let r_bytes = FieldBytes::clone_from_slice(r_bytes);
    if bool::from(FieldElement::from_bytes(&r_bytes).is_none()) {
        return Err(rejected);
    }
    let signature_scalar =
        Option::<Scalar>::from(Scalar::from_repr(FieldBytes::clone_from_slice(s_bytes)))
            .ok_or(rejected.clone())?;
    let encoded_key = EncodedPoint::from_bytes(public_key)
        .map_err(|_| BchScriptError::InvalidPublicKey { input_index })?;
    let key_point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded_key))
        .ok_or(BchScriptError::InvalidPublicKey { input_index })?;

    let mut challenge = Sha256::new();
    challenge.update(r_bytes);
    challenge.update(key_point.to_encoded_point(true).as_bytes());
    challenge.update(digest);
    let challenge_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&challenge.finalize());

    let nonce_point = ProjectivePoint::GENERATOR * signature_scalar
        - ProjectivePoint::from(key_point) * challenge_scalar;
    if bool::from(nonce_point.is_identity()) {
        return Err(rejected);
    }
    let nonce_encoded = nonce_point.to_affine().to_encoded_point(false);
    let (Some(nonce_x), Some(nonce_y)) = (nonce_encoded.x(), nonce_encoded.y()) else {
        return Err(rejected);
    };
    if *nonce_x != r_bytes {
        return Err(rejected);
    }
    let y_is_residue = Option::<FieldElement>::from(FieldElement::from_bytes(nonce_y))
        .is_some_and(|nonce_y| bool::from(nonce_y.sqrt().is_some()));
    if !y_is_residue {
        return Err(rejected);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::deserialize_hex;
    use bitcoin::{Amount, ScriptBuf, Witness};
    use k256::elliptic_curve::ops::Neg;

    use crate::test_utils::{
        BCH_TRANSFER_ECDSA_ALL, BCH_TRANSFER_ECDSA_ALL_UNCOMPRESSED,
        BCH_TRANSFER_ECDSA_ALL_WITHOUT_FORK_ID, BCH_TRANSFER_ECDSA_NONE, BCH_TRANSFER_SCHNORR_ALL,
        BCH_TRANSFER_SCHNORR_ALL_ANYONE_CAN_PAY, BCH_TRANSFER_SCHNORR_ALL_UNCOMPRESSED,
        BCH_TRANSFER_SCHNORR_SINGLE, BCH_TRANSFER_SCRIPT_PUBKEY,
        BCH_TRANSFER_UNCOMPRESSED_SCRIPT_PUBKEY,
    };

    #[test]
    fn schnorr_all_signed_by_bchn_verifies() {
        let transaction: Transaction = deserialize_hex(BCH_TRANSFER_SCHNORR_ALL).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(verify_transaction(&transaction, &spent), Ok(()));
    }

    #[test]
    fn ecdsa_all_signed_by_bchn_verifies() {
        let transaction: Transaction = deserialize_hex(BCH_TRANSFER_ECDSA_ALL).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(verify_transaction(&transaction, &spent), Ok(()));
    }

    #[test]
    fn ecdsa_with_an_uncompressed_key_signed_by_bchn_verifies() {
        let transaction: Transaction =
            deserialize_hex(BCH_TRANSFER_ECDSA_ALL_UNCOMPRESSED).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_UNCOMPRESSED_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(verify_transaction(&transaction, &spent), Ok(()));
    }

    #[test]
    fn ecdsa_none_signed_by_bchn_verifies_and_ignores_the_outputs() {
        let mut transaction: Transaction = deserialize_hex(BCH_TRANSFER_ECDSA_NONE).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(verify_transaction(&transaction, &spent), Ok(()));

        transaction.output[0].value = Amount::from_sat(1);
        assert_eq!(verify_transaction(&transaction, &spent), Ok(()));
    }

    #[test]
    fn schnorr_single_signed_by_bchn_commits_each_input_to_its_own_output() {
        let mut transaction: Transaction = deserialize_hex(BCH_TRANSFER_SCHNORR_SINGLE).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(verify_transaction(&transaction, &spent), Ok(()));

        transaction.output[1].value = Amount::from_sat(4_000);
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::SignatureRejected { input_index: 1 })
        );
    }

    #[test]
    fn schnorr_anyone_can_pay_signed_by_bchn_verifies_without_the_other_input() {
        let mut transaction: Transaction =
            deserialize_hex(BCH_TRANSFER_SCHNORR_ALL_ANYONE_CAN_PAY).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script.clone(),
                },
            ),
        ];
        assert_eq!(verify_transaction(&transaction, &spent), Ok(()));

        transaction.input.truncate(1);
        let first_only = [(
            0,
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: script,
            },
        )];
        assert_eq!(verify_transaction(&transaction, &first_only), Ok(()));
    }

    #[test]
    fn a_bitcoin_signature_without_fork_id_is_rejected() {
        let transaction: Transaction =
            deserialize_hex(BCH_TRANSFER_ECDSA_ALL_WITHOUT_FORK_ID).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::Sighash {
                input_index: 0,
                source: SighashError::MissingForkId(0x01),
            })
        );
    }

    #[test]
    fn schnorr_rejects_a_different_spent_amount() {
        let transaction: Transaction = deserialize_hex(BCH_TRANSFER_SCHNORR_ALL).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_001),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::SignatureRejected { input_index: 0 })
        );
    }

    #[test]
    fn ecdsa_all_rejects_a_changed_output() {
        let mut transaction: Transaction = deserialize_hex(BCH_TRANSFER_ECDSA_ALL).unwrap();
        transaction.output[1].value = Amount::from_sat(4_000);
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::SignatureRejected { input_index: 0 })
        );
    }

    #[test]
    fn schnorr_rejects_a_changed_nonce() {
        let mut transaction: Transaction = deserialize_hex(BCH_TRANSFER_SCHNORR_ALL).unwrap();
        let mut script_sig = transaction.input[0].script_sig.to_bytes();
        script_sig[1] ^= 0x01;
        transaction.input[0].script_sig = ScriptBuf::from_bytes(script_sig);
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::SignatureRejected { input_index: 0 })
        );
    }

    #[test]
    fn ecdsa_rejects_a_high_s_signature() {
        let mut transaction: Transaction = deserialize_hex(BCH_TRANSFER_ECDSA_ALL).unwrap();
        // Input 0 pushes 0x47 bytes: DER 30 44 02 20 <r> 02 20 <s>, then 0x41.
        let script_sig = transaction.input[0].script_sig.to_bytes();
        let der = &script_sig[1..71];
        let low_s = Scalar::from_repr(FieldBytes::clone_from_slice(&der[38..70])).unwrap();
        let high_s = low_s.neg().to_repr();
        let mut high_der = Vec::with_capacity(72);
        high_der.extend_from_slice(&[0x30, 0x45]);
        high_der.extend_from_slice(&der[2..36]);
        high_der.extend_from_slice(&[0x02, 0x21, 0x00]);
        high_der.extend_from_slice(&high_s);
        let mut high_script_sig = Vec::with_capacity(script_sig.len() + 1);
        high_script_sig.push(0x48);
        high_script_sig.extend_from_slice(&high_der);
        high_script_sig.push(0x41);
        high_script_sig.extend_from_slice(&script_sig[72..]);
        transaction.input[0].script_sig = ScriptBuf::from_bytes(high_script_sig);
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::HighS { input_index: 0 })
        );
    }

    #[test]
    fn ecdsa_rejects_padding_that_strict_der_forbids() {
        let mut transaction: Transaction = deserialize_hex(BCH_TRANSFER_ECDSA_ALL).unwrap();
        let script_sig = transaction.input[0].script_sig.to_bytes();
        let der = &script_sig[1..71];
        let mut padded_der = Vec::with_capacity(72);
        padded_der.extend_from_slice(&[0x30, 0x45, 0x02, 0x21, 0x00]);
        padded_der.extend_from_slice(&der[4..]);
        let mut padded_script_sig = Vec::with_capacity(script_sig.len() + 1);
        padded_script_sig.push(0x48);
        padded_script_sig.extend_from_slice(&padded_der);
        padded_script_sig.push(0x41);
        padded_script_sig.extend_from_slice(&script_sig[72..]);
        transaction.input[0].script_sig = ScriptBuf::from_bytes(padded_script_sig);
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::NonStrictDer { input_index: 0 })
        );
    }

    #[test]
    fn a_key_that_does_not_hash_to_the_output_is_rejected() {
        let transaction: Transaction = deserialize_hex(BCH_TRANSFER_SCHNORR_ALL).unwrap();
        let other = ScriptBuf::from_hex(BCH_TRANSFER_UNCOMPRESSED_SCRIPT_PUBKEY).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: other,
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::PublicKeyHashMismatch { input_index: 0 })
        );
    }

    #[test]
    fn a_p2sh_output_is_not_supported() {
        let transaction: Transaction = deserialize_hex(BCH_TRANSFER_SCHNORR_ALL).unwrap();
        let p2sh = ScriptBuf::from_hex("a9147b00ca78ec9935f4794bf1b1af2c08f2e33dfc7487").unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: p2sh,
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::UnsupportedScript { input_index: 0 })
        );
    }

    #[test]
    fn witness_data_is_rejected() {
        let mut transaction: Transaction = deserialize_hex(BCH_TRANSFER_SCHNORR_ALL).unwrap();
        transaction.input[1].witness = Witness::from_slice(&[[0x01u8]]);
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &spent),
            Err(BchScriptError::WitnessPresent { input_index: 1 })
        );
    }

    #[test]
    fn spent_outputs_out_of_input_order_are_rejected() {
        let transaction: Transaction = deserialize_hex(BCH_TRANSFER_SCHNORR_ALL).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_SCRIPT_PUBKEY).unwrap();
        let swapped = [
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
        ];
        assert_eq!(
            verify_transaction(&transaction, &swapped),
            Err(BchScriptError::SpentOutputsMismatch)
        );
        let one = [(
            0,
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: script,
            },
        )];
        assert_eq!(
            verify_transaction(&transaction, &one),
            Err(BchScriptError::SpentOutputsMismatch)
        );
    }

    #[test]
    fn schnorr_with_an_uncompressed_key_signed_by_bchn_verifies() {
        let transaction: Transaction =
            deserialize_hex(BCH_TRANSFER_SCHNORR_ALL_UNCOMPRESSED).unwrap();
        let script = ScriptBuf::from_hex(BCH_TRANSFER_UNCOMPRESSED_SCRIPT_PUBKEY).unwrap();
        let spent = [
            (
                0,
                TxOut {
                    value: Amount::from_sat(50_000),
                    script_pubkey: script.clone(),
                },
            ),
            (
                1,
                TxOut {
                    value: Amount::from_sat(70_000),
                    script_pubkey: script,
                },
            ),
        ];
        assert_eq!(verify_transaction(&transaction, &spent), Ok(()));
    }

    /// Nonce 3G has a Y coordinate that is not a square modulo p; nonce -3G
    /// has the same X and a square Y. Signatures over both share `r`, so only
    /// the quadratic-residue check tells them apart.
    #[test]
    fn schnorr_accepts_only_the_nonce_with_a_square_y() {
        let secret = Scalar::from(7u64);
        let public_key = (ProjectivePoint::GENERATOR * secret)
            .to_affine()
            .to_encoded_point(true);
        let digest = [0x5a; 32];
        let nonce = Scalar::from(3u64);
        let nonce_encoded = (ProjectivePoint::GENERATOR * nonce)
            .to_affine()
            .to_encoded_point(false);
        let nonce_x = nonce_encoded.x().unwrap();
        let mut challenge = Sha256::new();
        challenge.update(nonce_x);
        challenge.update(public_key.as_bytes());
        challenge.update(digest);
        let challenge_scalar = <Scalar as Reduce<U256>>::reduce_bytes(&challenge.finalize());

        let mut non_square_signature = Vec::with_capacity(64);
        non_square_signature.extend_from_slice(nonce_x);
        non_square_signature.extend_from_slice(&(nonce + challenge_scalar * secret).to_repr());
        let mut square_signature = Vec::with_capacity(64);
        square_signature.extend_from_slice(nonce_x);
        square_signature.extend_from_slice(&(nonce.neg() + challenge_scalar * secret).to_repr());

        assert_eq!(
            verify_schnorr(&non_square_signature, public_key.as_bytes(), &digest, 0),
            Err(BchScriptError::SignatureRejected { input_index: 0 })
        );
        assert_eq!(
            verify_schnorr(&square_signature, public_key.as_bytes(), &digest, 0),
            Ok(())
        );
    }

    #[test]
    fn schnorr_rejects_an_r_not_below_the_field_size() {
        let public_key = (ProjectivePoint::GENERATOR * Scalar::from(7u64))
            .to_affine()
            .to_encoded_point(true);
        let mut signature = [0x01u8; 64];
        signature[..32].copy_from_slice(&[0xff; 32]);
        assert_eq!(
            verify_schnorr(&signature, public_key.as_bytes(), &[0x5a; 32], 0),
            Err(BchScriptError::SignatureRejected { input_index: 0 })
        );
    }

    #[test]
    fn hybrid_public_keys_are_rejected() {
        assert!(!is_compressed_or_uncompressed(&[0x06; 65]));
        assert!(!is_compressed_or_uncompressed(&[0x07; 65]));
        assert!(is_compressed_or_uncompressed(&[0x04; 65]));
        assert!(is_compressed_or_uncompressed(&[0x02; 33]));
    }
}
