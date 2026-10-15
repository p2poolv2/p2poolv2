// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validate the miner's BCH job before installing it in a mining channel.

use super::session::DeclaredJob;
use crate::shares::bch_coinbase::BchCoinbase;
use crate::shares::coinbase_proof::MAX_COINBASE_MERKLE_BRANCH_LENGTH;
use crate::shares::merge_mining::MergeMiningCommitment;
use crate::shares::share_commitment::ShareCommitment;
use crate::stratum::work::block_template::TemplateTransaction;
use crate::stratum::work::coinbase::{EXTRANONCE_SEPARATOR, build_declared_coinbase};
use crate::stratum::work::gbt::{
    build_merkle_branches_for_template, compute_merkle_root_from_branches,
};
use crate::stratum::work::tracker::JobDetails;
use crate::utils::time_provider::{SystemTimeProvider, TimeProvider};
use bitcoin::block::{Header, Version};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Block, BlockHash, CompactTarget, TxMerkleNode, TxOut};
use mining_sv2::SetCustomMiningJob;
use p2poolv2_wallet::share_owner::ShareOwner;
use std::str::FromStr;
use std::sync::Arc;

/// Coinbase-only jobs deliberately do not reveal their transaction list.
/// Their declarator must validate CTOR/consensus and broadcast found blocks.
pub(crate) fn validate_custom_job(
    request: &SetCustomMiningJob,
    declared: DeclaredJob,
    payout: Address,
    owner: ShareOwner,
    version_mask: i32,
) -> Result<(JobDetails, Option<Block>), String> {
    let original = declared.prepared.template();
    let prev_hash =
        BlockHash::from_str(&original.previousblockhash).map_err(|error| error.to_string())?;
    let bits =
        CompactTarget::from_unprefixed_hex(&original.bits).map_err(|error| error.to_string())?;
    let now = SystemTimeProvider.seconds_since_epoch();
    if request.prev_hash.as_bytes() != prev_hash.as_byte_array()
        || request.nbits != bits.to_consensus()
        || (request.version as i32 ^ original.version) & !version_mask != 0
        || request.min_ntime < original.mintime
        || u64::from(request.min_ntime) > now + 7200
    {
        return Err("invalid-header".into());
    }
    if request.coinbase_tx_version != 2
        || request.coinbase_tx_input_n_sequence != 0xffff_fffe
        || request.coinbase_tx_locktime != original.height.checked_sub(1).ok_or("invalid-height")?
    {
        return Err("invalid-coinbase-layout".into());
    }
    if !matches!(owner, ShareOwner::CashP2pkh(_)) {
        return Err("invalid-share-owner".into());
    }
    let outputs: Vec<TxOut> =
        deserialize(request.coinbase_tx_outputs.as_bytes()).map_err(|error| error.to_string())?;
    let aux_index = outputs
        .len()
        .checked_sub(3)
        .ok_or("missing-commitment-outputs")?;
    let merge_mining = MergeMiningCommitment::from_output(&outputs[aux_index])?;
    let value = outputs
        .iter()
        .try_fold(0u64, |total, output| {
            total.checked_add(output.value.to_sat())
        })
        .filter(|value| *value <= Amount::MAX_MONEY.to_sat())
        .ok_or("invalid-coinbase-value")?;
    let descriptor = BchCoinbase {
        prefix: request.coinbase_prefix.as_bytes().to_vec(),
        merge_mining,
    };
    descriptor.validate(u64::from(original.height))?;
    let mut commitment =
        ShareCommitment::from_mining_job_token(request.token.as_bytes(), payout, owner, value)
            .map_err(|error| error.to_string())?;
    commitment.bch_coinbase = Some(descriptor.clone());
    let distribution = declared
        .prepared
        .declared_outputs(value)
        .map_err(|error| error.to_string())?;
    let coinbase = build_declared_coinbase(
        &distribution,
        u64::from(original.height),
        commitment.hash(),
        &EXTRANONCE_SEPARATOR,
        &descriptor,
    )
    .map_err(|error| error.to_string())?;
    if coinbase.output != outputs {
        return Err("invalid-pplns-outputs".into());
    }
    let serialized = serialize(&coinbase);
    // The bounded scriptSig uses a one-byte length after version, vin count and outpoint.
    let nonce_offset = 4 + 1 + 36 + 1 + descriptor.prefix.len();
    let prefix = &serialized[..nonce_offset];
    let suffix = &serialized[nonce_offset + EXTRANONCE_SEPARATOR.len()..];
    if prefix.len() > 65535 || suffix.len() > 65535 {
        return Err("coinbase-too-large".into());
    }
    if let Some(declaration) = &declared.declaration
        && (declaration.version != request.version
            || declaration.prefix != prefix
            || declaration.suffix != suffix)
    {
        return Err("declaration-mismatch".into());
    }
    if request.merkle_path.len() > MAX_COINBASE_MERKLE_BRANCH_LENGTH {
        return Err("merkle-path-too-long".into());
    }
    let branches = request
        .merkle_path
        .iter()
        .map(|branch| {
            let bytes: [u8; 32] = branch.as_bytes().try_into().expect("SV2 U256 is 32 bytes");
            TxMerkleNode::from_byte_array(bytes)
        })
        .collect::<Vec<_>>();
    let mut template = original.as_ref().clone();
    template.version = request.version as i32;
    template.curtime = request.min_ntime;
    template.coinbasevalue = value;
    template.coinbaseaux.clear();
    template.default_witness_commitment = None;
    template.transactions = declared
        .transactions
        .as_ref()
        .map(|transactions| {
            transactions
                .iter()
                .map(|transaction| TemplateTransaction {
                    data: hex::encode(serialize(transaction)),
                    txid: transaction.compute_txid().to_string(),
                    hash: transaction.compute_wtxid().to_string(),
                    depends: Vec::new(),
                    fee: 0,
                    sigops: 0,
                    weight: 0,
                })
                .collect()
        })
        .unwrap_or_default();
    template.validate_bch().map_err(|error| error.to_string())?;
    template
        .validate_bch_block_size(&coinbase)
        .map_err(|error| error.to_string())?;
    let header = Header {
        version: Version::from_consensus(request.version as i32),
        prev_blockhash: prev_hash,
        merkle_root: compute_merkle_root_from_branches(coinbase.compute_txid(), &branches),
        time: request.min_ntime,
        bits,
        nonce: 0,
    };
    let block_available = declared.transactions.is_some();
    let proposal = if block_available {
        let expected = build_merkle_branches_for_template(&template)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(TxMerkleNode::from_raw_hash)
            .collect::<Vec<_>>();
        if expected != branches {
            return Err("invalid-merkle-path".into());
        }
        let mut txdata = Vec::with_capacity(template.transactions.len() + 1);
        txdata.push(coinbase);
        txdata.extend(
            declared
                .transactions
                .as_ref()
                .expect("full declaration")
                .iter()
                .cloned(),
        );
        Some(Block { header, txdata })
    } else {
        None
    };
    Ok((
        JobDetails {
            block_available,
            blocktemplate: Arc::new(template),
            coinbase1: hex::encode(prefix),
            coinbase2: hex::encode(suffix),
            generation_timestamp: now,
            share_commitment: Some(commitment),
            coinbase_nsecs: 0,
            template_merkle_branches: branches,
        },
        proposal,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{bch_template_transaction, test_bch_custom_job, test_bch_prepared};
    use binary_sv2::{B064K, Deserialize, Seq0255, U256};
    use bitcoin::Network;
    use p2poolv2_config::DEFAULT_VERSION_MASK;

    #[test]
    fn full_job_uses_declared_transactions_and_proportional_fee_revenue() {
        let prepared = test_bch_prepared();
        let token = prepared
            .mining_job_token([0x11; 32], prepared.template().curtime)
            .unwrap();
        let selected: bitcoin::Transaction =
            deserialize(&hex::decode(bch_template_transaction(1).data).unwrap()).unwrap();
        let (mut request_bytes, declared) =
            test_bch_custom_job(prepared, token, vec![selected.clone()], true, 5_000_000_004);
        let request = SetCustomMiningJob::from_bytes(&mut request_bytes).unwrap();
        let payout = Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
            Network::Regtest,
        );
        let (job, block) = validate_custom_job(
            &request,
            declared,
            payout,
            ShareOwner::CashP2pkh([0x22; 20]),
            DEFAULT_VERSION_MASK,
        )
        .unwrap();
        assert!(job.block_available);
        let block = block.unwrap();
        assert_eq!(block.txdata[1], selected);
        let outputs = &block.txdata[0].output;
        assert_eq!(outputs[0].value.to_sat(), 1_250_000_001);
        assert_eq!(outputs[1].value.to_sat(), 3_750_000_003);
        assert_eq!(
            job.share_commitment
                .unwrap()
                .bch_coinbase
                .unwrap()
                .merge_mining
                .merkle_root,
            [0x77; 32]
        );
    }

    #[test]
    fn private_job_preserves_hidden_merkle_path_without_pool_transactions() {
        let prepared = test_bch_prepared();
        let token = prepared
            .mining_job_token([0x11; 32], prepared.template().curtime)
            .unwrap();
        let selected =
            deserialize(&hex::decode(bch_template_transaction(7).data).unwrap()).unwrap();
        let (mut request_bytes, declared) =
            test_bch_custom_job(prepared, token, vec![selected], false, 5_000_000_000);
        let request = SetCustomMiningJob::from_bytes(&mut request_bytes).unwrap();
        let payout = Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
            Network::Regtest,
        );
        let (job, block) = validate_custom_job(
            &request,
            declared,
            payout,
            ShareOwner::CashP2pkh([0x22; 20]),
            DEFAULT_VERSION_MASK,
        )
        .unwrap();
        assert!(!job.block_available);
        assert!(block.is_none());
        assert!(job.blocktemplate.transactions.is_empty());
        assert_eq!(job.template_merkle_branches.len(), 1);
        assert_eq!(
            job.template_merkle_branches[0].as_byte_array(),
            request.merkle_path[0].as_array()
        );
    }

    #[test]
    fn full_job_rejects_wrong_merkle_path() {
        let prepared = test_bch_prepared();
        let token = prepared
            .mining_job_token([1; 32], prepared.template().curtime)
            .unwrap();
        let (mut request_bytes, declared) =
            test_bch_custom_job(prepared, token, vec![], true, 5_000_000_000);
        let mut request = SetCustomMiningJob::from_bytes(&mut request_bytes).unwrap();
        request.merkle_path = Seq0255::new(vec![U256::new(&[9; 32]).unwrap()]).unwrap();
        let payout = Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
            Network::Regtest,
        );
        assert_eq!(
            validate_custom_job(
                &request,
                declared,
                payout,
                ShareOwner::CashP2pkh([0x22; 20]),
                DEFAULT_VERSION_MASK
            )
            .unwrap_err(),
            "invalid-merkle-path"
        );
    }

    #[test]
    fn private_job_rejects_diverted_pplns_payment() {
        let prepared = test_bch_prepared();
        let token = prepared
            .mining_job_token([1; 32], prepared.template().curtime)
            .unwrap();
        let (mut request_bytes, declared) =
            test_bch_custom_job(prepared, token, vec![], false, 5_000_000_000);
        let mut request = SetCustomMiningJob::from_bytes(&mut request_bytes).unwrap();
        let mut outputs: Vec<TxOut> = deserialize(request.coinbase_tx_outputs.as_bytes()).unwrap();
        outputs[0].value += Amount::from_sat(1);
        outputs[1].value -= Amount::from_sat(1);
        let changed_outputs = serialize(&outputs);
        request.coinbase_tx_outputs = B064K::new(&changed_outputs).unwrap();
        let payout = Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
            Network::Regtest,
        );
        assert_eq!(
            validate_custom_job(
                &request,
                declared,
                payout,
                ShareOwner::CashP2pkh([0x22; 20]),
                DEFAULT_VERSION_MASK
            )
            .unwrap_err(),
            "invalid-pplns-outputs"
        );
    }

    #[test]
    fn full_job_rejects_changed_declaration() {
        let prepared = test_bch_prepared();
        let token = prepared
            .mining_job_token([1; 32], prepared.template().curtime)
            .unwrap();
        let (mut request_bytes, mut declared) =
            test_bch_custom_job(prepared, token, vec![], true, 5_000_000_000);
        let request = SetCustomMiningJob::from_bytes(&mut request_bytes).unwrap();
        declared.declaration.as_mut().unwrap().suffix[0] ^= 1;
        let payout = Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
            Network::Regtest,
        );
        assert_eq!(
            validate_custom_job(
                &request,
                declared,
                payout,
                ShareOwner::CashP2pkh([0x22; 20]),
                DEFAULT_VERSION_MASK
            )
            .unwrap_err(),
            "declaration-mismatch"
        );
    }
}
