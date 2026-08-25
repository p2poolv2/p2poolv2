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

//! Integration tests for receiving share blocks and organising them into the
//! candidate and confirmed chains.
//!
//! These drive the real store through its writer thread (no mocks): each block
//! is received exactly as the node receives one -- stored, organised into the
//! candidate chain, marked BlockValid (standing in for ingest validation having
//! accepted it), and then organised into the confirmed chain. Confirmation is
//! deliberately deferred in some scenarios so that several blocks are promoted
//! by a single `organise_block`, which is what lets a conflict between two
//! already-validated blocks reach the confirmation path.

use bitcoin::hashes::Hash;
use p2poolv2_lib::pool_difficulty::PoolDifficulty;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::shares::share_block::ShareBlock;
use p2poolv2_lib::shares::validation::{DefaultShareValidator, ShareValidator};
use p2poolv2_lib::store::block_tx_metadata::Status;
use p2poolv2_lib::test_utils::{TestShareBlockBuilder, setup_test_chain_store_handle};

/// Base timestamp for received blocks; each block advances it.
const FIRST_BLOCK_TIME: u32 = 1_700_000_000;

/// A transaction spending `previous_output`. The value distinguishes otherwise
/// identical spends so two of them have different txids.
fn spending_transaction(previous_output: bitcoin::OutPoint, value: u64) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    }
}

/// A coinbase-shaped transaction, used to give a block an output that no other
/// block provides. Every builder block shares one coinbase txid, so a block's
/// own coinbase cannot serve as a source unique to it.
fn funding_transaction(value: u64) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), u32::MAX),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(value),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    }
}

/// Receive a block without organising the confirmed chain: store it, place it
/// on the candidate chain, and mark it BlockValid as ingest validation would.
async fn receive_block(chain_store_handle: &ChainStoreHandle, block: &ShareBlock) {
    chain_store_handle
        .add_share_block(block.clone())
        .await
        .unwrap();
    chain_store_handle
        .organise_header(block.header.clone())
        .await
        .unwrap();
    chain_store_handle
        .mark_block_valid(block.block_hash())
        .await
        .unwrap();
}

/// Receive a block and immediately organise the confirmed chain, as the node
/// does for a block that arrives on its own.
async fn receive_and_organise(chain_store_handle: &ChainStoreHandle, block: &ShareBlock) {
    receive_block(chain_store_handle, block).await;
    chain_store_handle.organise_block().await.unwrap();
}

/// A validator for the ingest-time prevout checks. Only `validate_prevouts` is
/// exercised, which does not consult pool difficulty, so the anchor is
/// arbitrary.
fn ingest_validator() -> DefaultShareValidator {
    DefaultShareValidator::new(
        PoolDifficulty::new(
            bitcoin::CompactTarget::from_consensus(0x1d00ffff),
            FIRST_BLOCK_TIME,
            0,
        ),
        1,
        b"P2Poolv2".to_vec(),
    )
}

/// Receive a block and run the real ingest-time prevout validation over it,
/// resolving its status the way the organise worker does: a consensus failure
/// marks the block Invalid, anything else marks it BlockValid.
///
/// The other receive helpers mark BlockValid unconditionally, which presumes
/// the verdict this is here to observe.
async fn receive_block_with_prevout_validation(
    chain_store_handle: &ChainStoreHandle,
    block: &ShareBlock,
) {
    chain_store_handle
        .add_share_block(block.clone())
        .await
        .unwrap();
    chain_store_handle
        .organise_header(block.header.clone())
        .await
        .unwrap();
    match ingest_validator().validate_prevouts(block, chain_store_handle) {
        Ok(()) => chain_store_handle
            .mark_block_valid(block.block_hash())
            .await
            .unwrap(),
        Err(_) => chain_store_handle
            .mark_invalid(block.block_hash())
            .await
            .unwrap(),
    }
}

/// A chain of received blocks is confirmed one height at a time.
#[tokio::test]
async fn test_linear_chain_confirms_every_received_block() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

    let genesis = TestShareBlockBuilder::new()
        .nonce(0xa0000001)
        .time(FIRST_BLOCK_TIME)
        .build();
    chain_store_handle
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    let mut parent = genesis;
    for index in 1..=3u32 {
        let block = TestShareBlockBuilder::new()
            .prev_share_blockhash(parent.block_hash().to_string())
            .nonce(0xa0000001 + index)
            .time(FIRST_BLOCK_TIME + index)
            .build();
        receive_and_organise(&chain_store_handle, &block).await;

        assert_eq!(
            chain_store_handle.get_tip_height().unwrap(),
            Some(index),
            "the confirmed chain follows each received block"
        );
        assert!(chain_store_handle.is_block_confirmed(&block.block_hash()));
        parent = block;
    }
}

/// A heavier fork that grows past the confirmed tip reorgs the confirmed chain
/// onto it.
///
/// The fork has to reach beyond the confirmed tip to be promoted: candidates
/// are only scanned from one above the confirmed height, so a fork block level
/// with the tip is not on its own a promotion candidate.
#[tokio::test]
async fn test_heavier_fork_reorgs_the_confirmed_chain() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

    let genesis = TestShareBlockBuilder::new()
        .nonce(0xb0000001)
        .time(FIRST_BLOCK_TIME)
        .build();
    chain_store_handle
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    let first = TestShareBlockBuilder::new()
        .prev_share_blockhash(genesis.block_hash().to_string())
        .nonce(0xb0000002)
        .time(FIRST_BLOCK_TIME + 1)
        .build();
    receive_and_organise(&chain_store_handle, &first).await;
    assert!(chain_store_handle.is_block_confirmed(&first.block_hash()));

    // A sibling of `first` carrying more work, extended by a second block so
    // the fork rises above the confirmed tip.
    let fork_first = TestShareBlockBuilder::new()
        .prev_share_blockhash(genesis.block_hash().to_string())
        .work(4)
        .nonce(0xb0000003)
        .time(FIRST_BLOCK_TIME + 2)
        .build();
    let fork_second = TestShareBlockBuilder::new()
        .prev_share_blockhash(fork_first.block_hash().to_string())
        .work(4)
        .nonce(0xb0000004)
        .time(FIRST_BLOCK_TIME + 3)
        .build();
    receive_block(&chain_store_handle, &fork_first).await;
    receive_and_organise(&chain_store_handle, &fork_second).await;

    assert_eq!(chain_store_handle.get_tip_height().unwrap(), Some(2));
    assert!(
        chain_store_handle.is_block_confirmed(&fork_first.block_hash())
            && chain_store_handle.is_block_confirmed(&fork_second.block_hash()),
        "the heavier fork takes over the confirmed chain"
    );
    assert!(
        !chain_store_handle.is_block_confirmed(&first.block_hash()),
        "the replaced block leaves the confirmed chain"
    );
}

/// Two received blocks on the same chain that spend the same output are both
/// accepted at ingest, because neither one's spend is confirmed while the other
/// is validated. Only the first may be confirmed.
#[tokio::test]
async fn test_same_chain_double_spend_confirms_only_the_first_block() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

    let genesis = TestShareBlockBuilder::new()
        .nonce(0xc0000001)
        .time(FIRST_BLOCK_TIME)
        .build();
    chain_store_handle
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    // Both blocks spend an output of the confirmed genesis block.
    let source_outpoint = bitcoin::OutPoint::new(genesis.transactions[0].0.compute_txid(), 0);
    let first_spender = TestShareBlockBuilder::new()
        .prev_share_blockhash(genesis.block_hash().to_string())
        .nonce(0xc0000002)
        .time(FIRST_BLOCK_TIME + 1)
        .add_transaction(spending_transaction(source_outpoint, 1_000))
        .build();
    let second_spender = TestShareBlockBuilder::new()
        .prev_share_blockhash(first_spender.block_hash().to_string())
        .nonce(0xc0000003)
        .time(FIRST_BLOCK_TIME + 2)
        .add_transaction(spending_transaction(source_outpoint, 900))
        .build();

    // Receive both before organising, so a single organise_block promotes them
    // together and the conflict has to be caught at confirmation.
    receive_block(&chain_store_handle, &first_spender).await;
    receive_block(&chain_store_handle, &second_spender).await;
    chain_store_handle.organise_block().await.unwrap();

    assert_eq!(
        chain_store_handle.get_tip_height().unwrap(),
        Some(1),
        "confirmation stops below the double-spending block"
    );
    assert!(chain_store_handle.is_block_confirmed(&first_spender.block_hash()));
    assert!(
        !chain_store_handle.is_block_confirmed(&second_spender.block_hash()),
        "the second spend of the same output must not be confirmed"
    );
    assert_eq!(
        chain_store_handle
            .get_block_metadata(&second_spender.block_hash())
            .unwrap()
            .status,
        Status::Invalid
    );
}

/// A fork block that spends an output produced by the block the reorg removes
/// must not be confirmed, even though it was valid when it was received.
#[tokio::test]
async fn test_reorg_rejects_fork_block_spending_reorged_out_source() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

    let genesis = TestShareBlockBuilder::new()
        .nonce(0xd0000001)
        .time(FIRST_BLOCK_TIME)
        .build();
    chain_store_handle
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    // The confirmed block carries a funding output that exists only in it.
    let funding_tx = funding_transaction(7_777);
    let source_outpoint = bitcoin::OutPoint::new(funding_tx.compute_txid(), 0);
    let confirmed_block = TestShareBlockBuilder::new()
        .prev_share_blockhash(genesis.block_hash().to_string())
        .nonce(0xd0000002)
        .time(FIRST_BLOCK_TIME + 1)
        .add_transaction(funding_tx)
        .build();
    receive_and_organise(&chain_store_handle, &confirmed_block).await;
    assert!(chain_store_handle.is_block_confirmed(&confirmed_block.block_hash()));

    // A heavier fork off genesis. Its second block spends the funding output,
    // which was still confirmed when that block was received.
    let fork_first = TestShareBlockBuilder::new()
        .prev_share_blockhash(genesis.block_hash().to_string())
        .work(4)
        .nonce(0xd0000003)
        .time(FIRST_BLOCK_TIME + 2)
        .build();
    let fork_spender = TestShareBlockBuilder::new()
        .prev_share_blockhash(fork_first.block_hash().to_string())
        .work(4)
        .nonce(0xd0000004)
        .time(FIRST_BLOCK_TIME + 3)
        .add_transaction(spending_transaction(source_outpoint, 1_000))
        .build();

    // Receive both fork blocks before organising, so one organise_block both
    // reorgs the confirmed chain and promotes the fork.
    receive_block(&chain_store_handle, &fork_first).await;
    receive_block(&chain_store_handle, &fork_spender).await;
    chain_store_handle.organise_block().await.unwrap();

    assert_eq!(
        chain_store_handle.get_tip_height().unwrap(),
        Some(1),
        "the reorg stops below the fork block whose source it removed"
    );
    assert!(
        chain_store_handle.is_block_confirmed(&fork_first.block_hash()),
        "the fork block that stays valid is confirmed"
    );
    assert!(
        !chain_store_handle.is_block_confirmed(&confirmed_block.block_hash()),
        "the reorged-out block leaves the confirmed chain"
    );
    assert!(
        !chain_store_handle.is_block_confirmed(&fork_spender.block_hash()),
        "its source left the confirmed chain, so it must not be confirmed"
    );
    assert_eq!(
        chain_store_handle
            .get_block_metadata(&fork_spender.block_hash())
            .unwrap()
            .status,
        Status::Invalid
    );
}

/// A heavier fork whose block spends the same output the confirmed chain
/// already spent is adopted once the fork outweighs the confirmed chain.
///
/// The same transaction appearing on both sides of a fork is the ordinary
/// situation in a reorg. `SpendsIndex` records only what the *currently*
/// confirmed chain spent, so asking "is this outpoint already spent?" at ingest
/// answers for the branch that happened to confirm first. Recording that answer
/// as a permanent `Invalid` would bar the fork through
/// `reorg_branch_has_invalid` and `all_in_zone_blocks_block_valid`, no matter
/// how much work it accumulated. The question is left to
/// `recheck_block_prevouts_with_overlay`, which asks it while the reorg is
/// being applied and knows the confirmed spend is being rewound.
#[tokio::test]
async fn test_reorg_adopts_heavier_fork_respending_an_outpoint_the_reorg_removes() {
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

    let genesis = TestShareBlockBuilder::new()
        .nonce(0xe0000001)
        .time(FIRST_BLOCK_TIME)
        .build();
    chain_store_handle
        .init_or_setup_genesis(genesis.clone())
        .await
        .unwrap();

    // A confirmed block below the fork point holds the output the fork will
    // contest. It is a spend of the genesis coinbase, so the contested output
    // is not itself a coinbase and the spenders below are judged on their
    // prevouts rather than on maturity.
    let funding_tx = spending_transaction(
        bitcoin::OutPoint::new(genesis.transactions[0].0.compute_txid(), 0),
        40_000,
    );
    let source_outpoint = bitcoin::OutPoint::new(funding_tx.compute_txid(), 0);
    let funding_block = TestShareBlockBuilder::new()
        .prev_share_blockhash(genesis.block_hash().to_string())
        .nonce(0xe0000002)
        .time(FIRST_BLOCK_TIME + 1)
        .add_transaction(funding_tx)
        .build();
    receive_and_organise(&chain_store_handle, &funding_block).await;
    assert!(chain_store_handle.is_block_confirmed(&funding_block.block_hash()));

    // One transaction, included on both sides of the fork, spending that output.
    let contested_tx = spending_transaction(source_outpoint, 1_000);

    let confirmed_spender = TestShareBlockBuilder::new()
        .prev_share_blockhash(funding_block.block_hash().to_string())
        .nonce(0xe0000003)
        .time(FIRST_BLOCK_TIME + 2)
        .add_transaction(contested_tx.clone())
        .build();
    receive_block_with_prevout_validation(&chain_store_handle, &confirmed_spender).await;
    chain_store_handle.organise_block().await.unwrap();
    assert!(
        chain_store_handle.is_block_confirmed(&confirmed_spender.block_hash()),
        "the first spender confirms, putting its spend in SpendsIndex"
    );

    // A heavier fork off the funding block carrying the same transaction,
    // extended so the fork rises above the confirmed tip and becomes a
    // promotion candidate.
    let fork_spender = TestShareBlockBuilder::new()
        .prev_share_blockhash(funding_block.block_hash().to_string())
        .work(4)
        .nonce(0xe0000004)
        .time(FIRST_BLOCK_TIME + 3)
        .add_transaction(contested_tx)
        .build();
    let fork_second = TestShareBlockBuilder::new()
        .prev_share_blockhash(fork_spender.block_hash().to_string())
        .work(4)
        .nonce(0xe0000005)
        .time(FIRST_BLOCK_TIME + 4)
        .build();
    receive_block_with_prevout_validation(&chain_store_handle, &fork_spender).await;
    receive_block_with_prevout_validation(&chain_store_handle, &fork_second).await;

    assert_ne!(
        chain_store_handle
            .get_block_metadata(&fork_spender.block_hash())
            .unwrap()
            .status,
        Status::Invalid,
        "ingest must not settle a question a reorg can change"
    );

    chain_store_handle.organise_block().await.unwrap();

    assert_eq!(
        chain_store_handle.get_tip_height().unwrap(),
        Some(3),
        "the heavier fork is adopted in full"
    );
    assert!(
        chain_store_handle.is_block_confirmed(&fork_spender.block_hash())
            && chain_store_handle.is_block_confirmed(&fork_second.block_hash()),
        "the fork block re-spending the outpoint confirms once the reorg removes the earlier spend"
    );
    assert!(
        !chain_store_handle.is_block_confirmed(&confirmed_spender.block_hash()),
        "the replaced spender leaves the confirmed chain"
    );
}
