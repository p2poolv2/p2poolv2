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

//! Synthetic share construction.
//!
//! Builds an [`Emission`] that is structurally identical to one a real stratum
//! miner would produce, except the header nonce satisfies no target (PoW is
//! stubbed under the `sim` feature). It reuses the real work-building path:
//! [`build_notify_from_prepared`] inserts a per-miner job (commitment +
//! coinbase + merkle branches + nsecs), and the bitcoin header is assembled
//! from the job exactly as `validate_bitcoin_difficulty` does, so the bitcoin
//! header merkle root matches what the receive-side `validate_bitcoin_payout`
//! reconstructs. See `docs/simulation/load-test-plan.md`.

use crate::accounting::payout::simple_pplns::SimplePplnsShare;
use crate::shares::extranonce::Extranonce;
use crate::stratum::emission::Emission;
use crate::stratum::work::difficulty::validate::build_coinbase_from_components;
use crate::stratum::work::gbt::compute_merkle_root_from_branches;
use crate::stratum::work::prepared_notify::{PreparedNotifyParams, build_notify_from_prepared};
use crate::stratum::work::tracker::JobTracker;
use bitcoin::block::Header;
use bitcoin::{Address, BlockHash, CompactTarget};
use std::str::FromStr;

/// A synthetic share ready to emit, plus the bitcoin coinbase it was built
/// with (reused on a block-find to assemble the real regtest block, since the
/// coinbase already carries the PPLNS payout distribution).
pub struct BuiltShare {
    pub emission: Emission,
    pub coinbase: bitcoin::Transaction,
}

/// Error building a synthetic share.
#[derive(Debug)]
pub struct SimShareError(pub String);

impl std::fmt::Display for SimShareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sim share error: {}", self.0)
    }
}

impl std::error::Error for SimShareError {}

/// Inputs to build one synthetic share emission.
pub struct SimShareParams<'a> {
    /// Prepared notify parameters for the current template + share-chain tip.
    pub prepared: &'a PreparedNotifyParams,
    /// This node's payout identity.
    pub miner_address: &'a Address,
    /// Job tracker the per-miner job is inserted into.
    pub tracker: &'a JobTracker,
    /// PPLNS user id (accounting only).
    pub user_id: u64,
    /// Share difficulty for PPLNS accounting (diff-1 relative).
    pub difficulty: u64,
    /// Payout address string for PPLNS accounting.
    pub btcaddress: String,
    /// Worker name for PPLNS accounting.
    pub workername: String,
    /// Pool-assigned extranonce1 (4 bytes) as hex (8 chars).
    pub enonce1_hex: &'a str,
    /// Miner extranonce2 (8 bytes) as hex (16 chars).
    pub enonce2_hex: &'a str,
    /// Header nonce (arbitrary — PoW is not satisfied).
    pub nonce: u32,
    /// Header time (seconds since epoch).
    pub ntime: u32,
}

/// Build a synthetic [`Emission`] for one share.
///
/// Inserts a per-miner job into `tracker`, assembles a bitcoin header whose
/// merkle root is consistent with the job's coinbase + template branches, and
/// returns the emission ready to be sent on the emissions channel (where the
/// normal pipeline — `handle_stratum_share` → store → broadcast — takes over).
pub fn build_sim_emission(params: SimShareParams<'_>) -> Result<BuiltShare, SimShareError> {
    // Insert a per-miner job: commitment, per-miner coinbase2, nsecs, branches.
    build_notify_from_prepared(params.prepared, Some(params.miner_address), params.tracker)
        .map_err(|e| SimShareError(format!("build notify: {e}")))?;

    let job_id = params.tracker.get_latest_job_id();
    let job = params
        .tracker
        .get_job(job_id)
        .ok_or_else(|| SimShareError("job missing from tracker after insert".into()))?;

    // Assemble the bitcoin coinbase + merkle root exactly as
    // validate_bitcoin_difficulty does, so the receive-side merkle check passes.
    let coinbase = build_coinbase_from_components(
        &job.coinbase1,
        params.enonce1_hex,
        params.enonce2_hex,
        &job.coinbase2,
    )
    .map_err(|e| SimShareError(format!("build coinbase: {e}")))?;
    let merkle_root =
        compute_merkle_root_from_branches(coinbase.compute_txid(), &job.template_merkle_branches);

    let template = &job.blocktemplate;
    let prev_blockhash = BlockHash::from_str(&template.previousblockhash)
        .map_err(|e| SimShareError(format!("bad previousblockhash: {e}")))?;
    let bits = CompactTarget::from_unprefixed_hex(&template.bits)
        .map_err(|e| SimShareError(format!("bad bits: {e}")))?;

    // No version rolling in the sim: use the template version verbatim.
    let header = Header {
        version: bitcoin::block::Version::from_consensus(template.version),
        prev_blockhash,
        merkle_root,
        time: params.ntime,
        bits,
        nonce: params.nonce,
    };

    let extranonce = Extranonce::from_enonce_hex(params.enonce1_hex, params.enonce2_hex)
        .map_err(|e| SimShareError(format!("bad extranonce: {e}")))?;

    let pplns = SimplePplnsShare::new(
        params.user_id,
        params.difficulty,
        params.btcaddress,
        params.workername,
        params.ntime as u64,
        format!("{job_id:016x}"),
        params.enonce2_hex.to_string(),
        format!("{:08x}", params.nonce),
    );

    let emission = Emission {
        pplns,
        header,
        blocktemplate: job.blocktemplate.clone(),
        share_commitment: job.share_commitment.clone(),
        coinbase_nsecs: job.coinbase_nsecs,
        template_merkle_branches: job.template_merkle_branches.clone(),
        extranonce,
    };

    Ok(BuiltShare { emission, coinbase })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::OutputPair;
    use crate::shares::handle_stratum_share::handle_stratum_share;
    use crate::shares::share_commitment::ShareCommitment;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::stratum::work::coinbase::build_bitcoin_coinbase_transaction;
    use crate::stratum::work::prepared_notify::PreparedNotifyParamsBuilder;
    use crate::stratum::work::tracker::start_tracker_actor;
    use bitcoin::script::PushBytesBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, CompactTarget, CompressedPublicKey, Network};

    #[mockall_double::double]
    use crate::shares::chain::chain_store_handle::ChainStoreHandle;

    const POOL_SIGNATURE: &[u8] = b"sim_pool";

    fn test_template() -> BlockTemplate {
        let data =
            include_str!("../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json");
        serde_json::from_str(data).expect("parse BlockTemplate")
    }

    fn test_address() -> Address {
        let pubkey: CompressedPublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();
        Address::p2wpkh(&pubkey, Network::Regtest)
    }

    fn build_prepared(template: std::sync::Arc<BlockTemplate>) -> PreparedNotifyParams {
        let output_distribution = vec![OutputPair {
            address: test_address(),
            amount: Amount::from_sat(template.coinbasevalue),
        }];
        PreparedNotifyParamsBuilder::new(template, output_distribution, POOL_SIGNATURE, false)
            .bits(CompactTarget::from_consensus(0x1d00ffff))
            .build()
            .expect("prepared build")
    }

    /// The crux: a synthetic emission's bitcoin header merkle root must equal
    /// what the receive-side `validate_bitcoin_payout` reconstructs from the
    /// share header (commitment) + template branches. This proves a synthetic
    /// share will pass the bitcoin-merkle-root validation on peers.
    #[tokio::test]
    async fn emission_merkle_root_matches_validation_reconstruction() {
        let template = std::sync::Arc::new(test_template());
        let prepared = build_prepared(template.clone());
        let tracker = start_tracker_actor();
        let address = test_address();

        let output_distribution = vec![OutputPair {
            address: address.clone(),
            amount: Amount::from_sat(template.coinbasevalue),
        }];

        let emission = build_sim_emission(SimShareParams {
            prepared: &prepared,
            miner_address: &address,
            tracker: &tracker,
            user_id: 1,
            difficulty: 1,
            btcaddress: address.to_string(),
            workername: "sim".to_string(),
            enonce1_hex: "deadbeef",
            enonce2_hex: "0000000000000001",
            nonce: 0x12345678,
            ntime: 1_700_000_500,
        })
        .expect("build emission")
        .emission;

        // Run through the real pipeline to produce the ShareBlock peers see.
        let mut store = ChainStoreHandle::default();
        store.expect_add_share_block().returning(|_| Ok(()));
        let share_block = handle_stratum_share(emission, &store)
            .await
            .expect("handle ok")
            .expect("p2p share block");

        // Reconstruct the bitcoin coinbase exactly as validate_bitcoin_payout does.
        let commitment_hash = ShareCommitment::from_share_header(&share_block.header).hash();
        let flags = match &share_block.header.coinbaseaux_flags {
            Some(aux) => aux.to_push_bytes_buf(),
            None => PushBytesBuf::from(&[0u8]),
        };
        let reconstructed = build_bitcoin_coinbase_transaction(
            Version::TWO,
            &output_distribution,
            share_block.header.bitcoin_height as i64,
            flags,
            share_block.header.witness_commitment.as_ref(),
            POOL_SIGNATURE,
            Some(commitment_hash),
            share_block.header.coinbase_nsecs,
            Some(share_block.header.extranonce.as_bytes()),
        )
        .expect("reconstruct coinbase");

        let recomputed_root = compute_merkle_root_from_branches(
            reconstructed.compute_txid(),
            &share_block.template_merkle_branches,
        );

        assert_eq!(
            recomputed_root, share_block.header.bitcoin_header.merkle_root,
            "synthetic bitcoin header merkle root must match validation reconstruction"
        );
    }

    #[tokio::test]
    async fn emission_carries_commitment_and_extranonce() {
        let template = std::sync::Arc::new(test_template());
        let prepared = build_prepared(template.clone());
        let tracker = start_tracker_actor();
        let address = test_address();

        let emission = build_sim_emission(SimShareParams {
            prepared: &prepared,
            miner_address: &address,
            tracker: &tracker,
            user_id: 7,
            difficulty: 5,
            btcaddress: address.to_string(),
            workername: "sim".to_string(),
            enonce1_hex: "aabbccdd",
            enonce2_hex: "1122334455667788",
            nonce: 42,
            ntime: 1_700_000_600,
        })
        .expect("build emission")
        .emission;

        let commitment = emission.share_commitment.expect("commitment present");
        assert_eq!(commitment.miner_bitcoin_address, address);
        assert_eq!(
            emission.extranonce.as_bytes(),
            &[
                0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
            ]
        );
        assert_eq!(emission.header.nonce, 42);
        assert_eq!(emission.header.time, 1_700_000_600);
    }
}
