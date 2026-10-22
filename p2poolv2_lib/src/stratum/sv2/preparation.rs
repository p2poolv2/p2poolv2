// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prepare BCH coinbase bytes for an external Job Declaration client without
//! duplicating P2Pool's payout or share-commitment rules in that client.
//! This calculation grants no mining authorization: the SV2 listener still
//! checks its own token registry, payouts, template and submitted proof.

use crate::accounting::payout::payout_distribution::build_pplns_outputs;
use crate::shares::bch_coinbase::BchCoinbase;
use crate::shares::share_commitment::ShareCommitment;
use crate::stratum::work::coinbase::{EXTRANONCE_SEPARATOR, build_declared_coinbase};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount};
use std::collections::HashMap;

#[derive(Debug)]
pub struct PreparedCoinbase {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub token_hash: [u8; 32],
}

/// The caller obtains exact difficulty weights from the token's share-chain
/// anchor. Neither an empty window nor unavailable history has a fallback payee.
pub fn prepare_coinbase(
    token: &[u8],
    mut commitment: ShareCommitment,
    weights: &HashMap<Address, u128>,
    value: u64,
    height: u32,
    descriptor: BchCoinbase,
) -> Result<PreparedCoinbase, String> {
    if value > Amount::MAX_MONEY.to_sat() {
        return Err("coinbase revenue exceeds BCH monetary range".into());
    }
    for (address, rate) in [
        (&commitment.donation_address, commitment.donation),
        (&commitment.fee_address, commitment.fee),
    ] {
        if rate.is_some_and(|rate| rate > 10_000 || (rate > 0 && address.is_none())) {
            return Err("invalid payout cut in job token".into());
        }
    }
    descriptor
        .validate(u64::from(height))
        .map_err(str::to_owned)?;
    let outputs = build_pplns_outputs(
        value,
        weights,
        &commitment.donation_address,
        commitment.donation,
        &commitment.fee_address,
        commitment.fee,
    )
    .map_err(|error| error.to_string())?;
    commitment.bch_coinbase = Some(descriptor.clone());
    let coinbase = build_declared_coinbase(
        &outputs,
        u64::from(height),
        commitment.hash(),
        &EXTRANONCE_SEPARATOR,
        &descriptor,
    )
    .map_err(|error| error.to_string())?;
    let raw = serialize(&coinbase);
    // Version, singleton input count, null outpoint and bounded script length.
    let offset = 4 + 1 + 36 + 1 + descriptor.prefix.len();
    let end = offset + EXTRANONCE_SEPARATOR.len();
    if raw.get(offset..end) != Some(EXTRANONCE_SEPARATOR.as_slice()) {
        return Err("unexpected declared coinbase layout".into());
    }
    let prefix = raw[..offset].to_vec();
    let suffix = raw[end..].to_vec();
    if prefix.len() > 65535 || suffix.len() > 65535 {
        return Err("declared coinbase exceeds SV2 field limits".into());
    }
    Ok(PreparedCoinbase {
        prefix,
        suffix,
        token_hash: bitcoin::hashes::sha256::Hash::hash(token).to_byte_array(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::merge_mining::MergeMiningCommitment;
    use crate::test_utils::{test_bch_custom_job_with_aux, test_bch_prepared};
    use bitcoin::consensus::deserialize;
    use bitcoin::script::Builder;
    use bitcoin::{Network, PubkeyHash};
    use p2poolv2_wallet::share_owner::ShareOwner;

    #[test]
    fn full_preparation_matches_pplns_with_selected_fee_revenue() {
        let prepared = test_bch_prepared();
        let weights = HashMap::from([
            (
                Address::p2pkh(PubkeyHash::from_byte_array([1; 20]), Network::Regtest),
                1,
            ),
            (
                Address::p2pkh(PubkeyHash::from_byte_array([2; 20]), Network::Regtest),
                3,
            ),
        ]);
        let payout = Address::p2pkh(PubkeyHash::from_byte_array([0x22; 20]), Network::Regtest);
        let full = true;
        let value = 5_000_000_219;
        let token = prepared
            .mining_job_token([0x11; 32], prepared.template().curtime)
            .unwrap();
        let aux = MergeMiningCommitment {
            merkle_root: [0x77; 32],
            tree_size: 2,
            nonce: 9,
        };
        let commitment = ShareCommitment::from_mining_job_token(
            &token,
            payout.clone(),
            ShareOwner::CashP2pkh([0x22; 20]),
        )
        .unwrap();
        let descriptor = BchCoinbase {
            prefix: Builder::new()
                .push_int(i64::from(prepared.template().height))
                .push_slice(b"miner")
                .into_bytes(),
            merge_mining: aux,
        };
        let result = prepare_coinbase(
            &token,
            commitment,
            &weights,
            value,
            prepared.template().height,
            descriptor,
        )
        .unwrap();
        let (_, expected) =
            test_bch_custom_job_with_aux(prepared.clone(), token, vec![], full, value, aux);
        if let Some(declaration) = expected.declaration {
            assert_eq!(result.prefix, declaration.prefix);
            assert_eq!(result.suffix, declaration.suffix);
        }
        let mut raw = result.prefix;
        raw.extend(EXTRANONCE_SEPARATOR);
        raw.extend(result.suffix);
        let coinbase: bitcoin::Transaction = deserialize(&raw).unwrap();
        assert_eq!(
            coinbase
                .output
                .iter()
                .map(|out| out.value.to_sat())
                .sum::<u64>(),
            value
        );
        assert_eq!(
            MergeMiningCommitment::from_output(&coinbase.output[coinbase.output.len() - 3])
                .unwrap(),
            aux
        );
    }
    #[test]
    fn coinbase_only_preparation_preserves_pplns_and_aux_commitment() {
        let prepared = test_bch_prepared();
        let weights = HashMap::from([
            (
                Address::p2pkh(PubkeyHash::from_byte_array([1; 20]), Network::Regtest),
                1,
            ),
            (
                Address::p2pkh(PubkeyHash::from_byte_array([2; 20]), Network::Regtest),
                3,
            ),
        ]);
        let payout = Address::p2pkh(PubkeyHash::from_byte_array([0x22; 20]), Network::Regtest);
        let full = false;
        let value = 5_000_000_004;
        let token = prepared
            .mining_job_token([0x11; 32], prepared.template().curtime)
            .unwrap();
        let aux = MergeMiningCommitment {
            merkle_root: [0x77; 32],
            tree_size: 2,
            nonce: 9,
        };
        let commitment = ShareCommitment::from_mining_job_token(
            &token,
            payout.clone(),
            ShareOwner::CashP2pkh([0x22; 20]),
        )
        .unwrap();
        let descriptor = BchCoinbase {
            prefix: Builder::new()
                .push_int(i64::from(prepared.template().height))
                .push_slice(b"miner")
                .into_bytes(),
            merge_mining: aux,
        };
        let result = prepare_coinbase(
            &token,
            commitment,
            &weights,
            value,
            prepared.template().height,
            descriptor,
        )
        .unwrap();
        let (_, expected) =
            test_bch_custom_job_with_aux(prepared.clone(), token, vec![], full, value, aux);
        if let Some(declaration) = expected.declaration {
            assert_eq!(result.prefix, declaration.prefix);
            assert_eq!(result.suffix, declaration.suffix);
        }
        let mut raw = result.prefix;
        raw.extend(EXTRANONCE_SEPARATOR);
        raw.extend(result.suffix);
        let coinbase: bitcoin::Transaction = deserialize(&raw).unwrap();
        assert_eq!(
            coinbase
                .output
                .iter()
                .map(|out| out.value.to_sat())
                .sum::<u64>(),
            value
        );
        assert_eq!(
            MergeMiningCommitment::from_output(&coinbase.output[coinbase.output.len() - 3])
                .unwrap(),
            aux
        );
    }
}
