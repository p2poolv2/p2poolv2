// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bitcoin Cash share-chain genesis.
//!
//! Bitcoin genesis files stay as they are. A Bitcoin Cash node anchors its
//! share on the published BCHN genesis block for the selected network and
//! pays the NUMS key with P2PKH. Main and mini differ by their anchor target,
//! so the genesis hash differs and the chains do not reorg into each other.

use crate::config::{BchShareChain, BitcoinCashNetwork, Chain, StratumConfig};
use crate::shares::coinbase_proof::CoinbaseProof;
use crate::shares::genesis;
use crate::shares::share_block::{ShareBlock, ShareHeader, ShareTransaction};
use crate::shares::transactions::coinbase::build_sharechain_coinbase_transaction;
use crate::sim_overrides;
use bitcoin::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Block, CompactTarget, CompressedPublicKey, Network, PubkeyHash};
use p2poolv2_wallet::bch_share::BchShareNetwork;
use p2poolv2_wallet::share_owner::ShareOwner;
use std::error::Error;

/// Anchor target of the main share chain. This is the production value of
/// [`sim_overrides::anchor_target`] and is easier than [`crate::shares::share_block::MAX_POOL_TARGET`],
/// which remains the ceiling for shares after genesis.
pub const MAIN_ANCHOR_TARGET: u32 = 0x1b4188f5;

/// Anchor and ceiling of the mini share chain. The compact exponent is one
/// higher than [`crate::shares::share_block::MAX_POOL_TARGET`], which multiplies
/// the target by 256.
pub const MINI_ANCHOR_TARGET: u32 = 0x1c384bd7;

/// Published BCHN chipnet (and testnet4) genesis hash.
#[cfg(test)]
const CHIPNET_GENESIS_HASH: &str =
    "000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b";

/// Build the share genesis for this stratum config.
///
/// Bitcoin keeps [`ShareBlock::build_genesis_for_network`]. Bitcoin Cash uses
/// [`build`] and requires `bitcoin_cash_network`.
pub fn genesis_for_stratum<State>(
    stratum: &StratumConfig<State>,
) -> Result<ShareBlock, Box<dyn Error + Send + Sync>> {
    match stratum.chain {
        Chain::Bitcoin => ShareBlock::build_genesis_for_network(stratum.network),
        Chain::BitcoinCash => {
            let bitcoin_cash_network = stratum
                .bitcoin_cash_network
                .ok_or("bitcoin_cash_network is required")?;
            build(share_network(bitcoin_cash_network), stratum.bch_share_chain)
        }
    }
}

/// Share genesis for a Bitcoin Cash network and main or mini chain.
pub fn build(
    network: BchShareNetwork,
    share_chain: BchShareChain,
) -> Result<ShareBlock, Box<dyn Error + Send + Sync>> {
    let anchor = anchor_block(network);
    let genesis_data = genesis::genesis_data(Network::Regtest)
        .map_err(|error| -> Box<dyn Error + Send + Sync> { error.to_string().into() })?;
    let pubkey_hash = nums_pubkey_hash(genesis_data.public_key)?;
    let payout_network = payout_network(network);
    let miner_bitcoin_address = Address::p2pkh(pubkey_hash, payout_network);
    let miner_address = ShareOwner::CashP2pkh(pubkey_hash.to_byte_array());
    let coinbase =
        build_sharechain_coinbase_transaction(&miner_address, anchor.header.block_hash(), &[]);
    let transactions = vec![ShareTransaction(coinbase)];
    let header = ShareHeader {
        prev_share_blockhash: bitcoin::BlockHash::all_zeros(),
        uncles: vec![],
        miner_bitcoin_address,
        miner_address,
        bitcoin_header: anchor.header,
        time: sim_overrides::genesis_timestamp(&genesis_data),
        bits: anchor_bits(share_chain),
        donation_address: None,
        donation: None,
        fee_address: None,
        fee: None,
        bitcoin_height: 0,
        // The anchor block's coinbase predates the share chain and carries no
        // commitment. Genesis is built locally and never verified.
        coinbase_proof: CoinbaseProof::default(),
        bch_coinbase: None,
    };
    let bitcoin_coinbase = anchor
        .txdata
        .first()
        .cloned()
        .ok_or("Bitcoin Cash anchor block has no coinbase")?;
    Ok(ShareBlock {
        header,
        transactions,
        template_merkle_branches: vec![],
        bitcoin_coinbase,
    })
}

/// BCHN genesis block for `network`. Mainnet and regtest are the blocks
/// `bitcoin::constants::genesis_block` already builds. Chipnet uses the
/// timestamp, nonce, and bits published in BCHN `CChipNetParams`.
pub fn anchor_block(network: BchShareNetwork) -> Block {
    match network {
        BchShareNetwork::Mainnet => genesis_block(Network::Bitcoin),
        BchShareNetwork::Regtest => genesis_block(Network::Regtest),
        BchShareNetwork::Chipnet => chipnet_genesis_block(),
    }
}

/// Ceiling applied to share targets on the chain anchored at `anchor`.
///
/// Mini keeps its own easier ceiling. Every other anchor, including Bitcoin
/// and the Bitcoin Cash main chain, keeps [`crate::shares::share_block::MAX_POOL_TARGET`].
pub fn target_ceiling(anchor: CompactTarget) -> CompactTarget {
    if anchor.to_consensus() == MINI_ANCHOR_TARGET {
        CompactTarget::from_consensus(MINI_ANCHOR_TARGET)
    } else {
        CompactTarget::from_consensus(crate::shares::share_block::MAX_POOL_TARGET)
    }
}

fn chipnet_genesis_block() -> Block {
    let mut block = genesis_block(Network::Bitcoin);
    block.header.time = 1_597_811_185;
    block.header.bits = CompactTarget::from_consensus(0x1d00ffff);
    block.header.nonce = 114_152_193;
    block
}

fn anchor_bits(share_chain: BchShareChain) -> CompactTarget {
    match share_chain {
        BchShareChain::Main => sim_overrides::anchor_target(),
        BchShareChain::Mini => CompactTarget::from_consensus(MINI_ANCHOR_TARGET),
    }
}

fn payout_network(network: BchShareNetwork) -> Network {
    match network {
        BchShareNetwork::Mainnet => Network::Bitcoin,
        BchShareNetwork::Chipnet | BchShareNetwork::Regtest => Network::Regtest,
    }
}

fn nums_pubkey_hash(public_key: &str) -> Result<PubkeyHash, Box<dyn Error + Send + Sync>> {
    let key = public_key
        .parse::<CompressedPublicKey>()
        .map_err(|error| -> Box<dyn Error + Send + Sync> { error.to_string().into() })?;
    Ok(PubkeyHash::hash(&key.0.serialize()))
}

fn share_network(network: BitcoinCashNetwork) -> BchShareNetwork {
    match network {
        BitcoinCashNetwork::Mainnet => BchShareNetwork::Mainnet,
        BitcoinCashNetwork::Chipnet => BchShareNetwork::Chipnet,
        BitcoinCashNetwork::Regtest => BchShareNetwork::Regtest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2poolv2_wallet::share_owner::ShareOwner;

    #[test]
    fn mainnet_anchor_is_the_bch_genesis_block() {
        let block = anchor_block(BchShareNetwork::Mainnet);
        assert_eq!(
            block.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
    }

    #[test]
    fn regtest_anchor_is_the_bchn_regtest_genesis_block() {
        let block = anchor_block(BchShareNetwork::Regtest);
        assert_eq!(
            block.block_hash().to_string(),
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
    }

    #[test]
    fn chipnet_anchor_is_the_published_bchn_genesis_block() {
        let block = anchor_block(BchShareNetwork::Chipnet);
        assert_eq!(block.block_hash().to_string(), CHIPNET_GENESIS_HASH);
    }

    #[test]
    fn bitcoin_cash_genesis_pays_p2pkh_and_mini_is_a_different_chain() {
        let main = build(BchShareNetwork::Regtest, BchShareChain::Main).unwrap();
        let mini = build(BchShareNetwork::Regtest, BchShareChain::Mini).unwrap();
        assert!(matches!(
            main.header.miner_address,
            ShareOwner::CashP2pkh(_)
        ));
        assert!(main.header.miner_bitcoin_address.script_pubkey().is_p2pkh());
        assert_eq!(main.transactions[0].output.len(), 1);
        assert!(main.transactions[0].input[0].witness.is_empty());
        assert_ne!(main.block_hash(), mini.block_hash());
        assert_eq!(mini.header.bits.to_consensus(), MINI_ANCHOR_TARGET);
        assert_eq!(main.header.bits.to_consensus(), MAIN_ANCHOR_TARGET);
    }

    #[test]
    fn bitcoin_stratum_keeps_the_taproot_genesis() {
        let config = crate::config::StratumConfig::new_for_test_default();
        let genesis = genesis_for_stratum(&config).unwrap();
        assert!(matches!(
            genesis.header.miner_address,
            ShareOwner::Taproot(_)
        ));
    }
}
