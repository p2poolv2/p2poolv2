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

//! Benchmarks for PplnsWindow update and accumulate_weighted_difficulty.
//!
//! Fills the PPLNS window to its maximum capacity (120,960 confirmed entries)
//! with 10% uncle ratio, then benchmarks both operations.

use bitcoin::BlockHash;
use bitcoin::CompressedPublicKey;
use bitcoin::hashes::Hash;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use p2poolv2_lib::accounting::payout::sharechain_pplns::pplns_window::PplnsWindow;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::test_utils::{
    PUBKEY_2G, PUBKEY_3G, PUBKEY_4G, PUBKEY_5G, PUBKEY_G, TestShareBlockBuilder, genesis_for_tests,
    setup_test_chain_store_handle,
};
use tempfile::TempDir;

/// Total confirmed shares to fill the window (MAX_PPLNS_WINDOW_SHARES).
const TOTAL_CONFIRMED_SHARES: usize = 120_960;

/// Every Nth confirmed share references one uncle, yielding ~10% uncles.
const UNCLE_INTERVAL: usize = 10;

/// Base difficulty for benchmark shares.
const BASE_DIFFICULTY: f64 = 1024.0;

/// Miner pubkey strings used to derive distinct addresses.
const MINER_PUBKEYS: [&str; 5] = [PUBKEY_G, PUBKEY_2G, PUBKEY_3G, PUBKEY_4G, PUBKEY_5G];

/// Derive a Signet p2wpkh address string from a hex-encoded compressed pubkey.
fn address_from_pubkey(pubkey_hex: &str) -> String {
    let pubkey: CompressedPublicKey = pubkey_hex.parse().expect("valid test pubkey");
    bitcoin::Address::p2wpkh(&pubkey, bitcoin::Network::Signet).to_string()
}

/// Create a deterministic BlockHash from an index by filling a 32-byte array.
fn blockhash_from_index(index: usize) -> BlockHash {
    let mut bytes = [0u8; 32];
    let index_bytes = index.to_le_bytes();
    let copy_length = index_bytes.len().min(bytes.len());
    bytes[..copy_length].copy_from_slice(&index_bytes[..copy_length]);
    BlockHash::from_byte_array(bytes)
}

/// Build miner address strings from the well-known test pubkeys.
fn build_miner_addresses() -> Vec<String> {
    MINER_PUBKEYS
        .iter()
        .map(|pubkey_hex| address_from_pubkey(pubkey_hex))
        .collect()
}

/// Build a PplnsWindow pre-filled with confirmed shares and uncles.
///
/// Creates `share_count` confirmed entries with every `UNCLE_INTERVAL`th
/// entry referencing one uncle, giving roughly 10% uncle ratio.
fn build_benchmark_window(share_count: usize) -> PplnsWindow {
    let miner_addresses = build_miner_addresses();
    let miner_count = miner_addresses.len();

    let mut confirmed_shares: Vec<(BlockHash, String, f64, Vec<(String, f64)>)> =
        Vec::with_capacity(share_count);

    let mut uncle_counter: usize = 0;

    for share_index in 0..share_count {
        let miner_address = miner_addresses[share_index % miner_count].clone();
        let difficulty = BASE_DIFFICULTY + (share_index as f64) * 0.01;
        let blockhash = blockhash_from_index(share_index);

        let uncle_data = if share_index % UNCLE_INTERVAL == 0 {
            let uncle_miner = miner_addresses[(uncle_counter + 2) % miner_count].clone();
            let uncle_difficulty = BASE_DIFFICULTY * 0.8;
            uncle_counter += 1;
            vec![(uncle_miner, uncle_difficulty)]
        } else {
            Vec::new()
        };

        confirmed_shares.push((blockhash, miner_address, difficulty, uncle_data));
    }

    eprintln!("  populated {} confirmed entries", confirmed_shares.len());

    let mut window = PplnsWindow::default();
    window.populate_for_benchmark(confirmed_shares);
    window
}

fn bench_get_distribution(criterion: &mut Criterion) {
    let window = build_benchmark_window(TOTAL_CONFIRMED_SHARES);

    criterion.bench_function("get_distribution_full_window", |bencher| {
        bencher.iter(|| {
            black_box(window.get_distribution(f64::MAX));
        });
    });
}

/// Number of confirmed shares to populate the RocksDB-backed store.
const STORE_SHARE_COUNT: usize = 3;

/// Build a RocksDB-backed ChainStoreHandle populated with confirmed shares.
///
/// Creates a genesis block plus `share_count` additional shares, each
/// promoted to the confirmed chain. Returns the handle, TempDir (which
/// must stay alive to keep the store open), the tokio Runtime (which
/// must stay alive to keep the store writer background task running),
/// and the tip blockhash for extending the chain further.
fn build_store_with_confirmed_shares(
    share_count: usize,
) -> (
    ChainStoreHandle,
    TempDir,
    tokio::runtime::Runtime,
    BlockHash,
) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (chain_handle, temp_dir, tip_hash) = runtime.block_on(async {
        let (chain_handle, temp_dir) = setup_test_chain_store_handle(true).await;
        let genesis = genesis_for_tests();
        chain_handle
            .init_or_setup_genesis(genesis.clone())
            .await
            .unwrap();

        let mut prev_hash = genesis.block_hash();
        for index in 0..share_count {
            let pubkey = MINER_PUBKEYS[index % MINER_PUBKEYS.len()];
            let share = TestShareBlockBuilder::new()
                .prev_share_blockhash(prev_hash.to_string())
                .miner_pubkey(pubkey)
                .work(2)
                .build();
            prev_hash = share.block_hash();
            chain_handle
                .add_share_block(share.clone(), true)
                .await
                .unwrap();
            chain_handle
                .organise_header(share.header.clone())
                .await
                .unwrap();
            chain_handle.organise_block().await.unwrap();
            if index % 100 == 0 {
                eprintln!("  populated {index}/{share_count} shares");
            }
        }
        eprintln!("  populated {share_count}/{share_count} shares");

        (chain_handle, temp_dir, prev_hash)
    });
    (chain_handle, temp_dir, runtime, tip_hash)
}

criterion_group!(benches, bench_get_distribution);
criterion_main!(benches);
