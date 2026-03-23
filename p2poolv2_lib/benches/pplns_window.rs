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
use p2poolv2_lib::test_utils::{
    PUBKEY_2G, PUBKEY_3G, PUBKEY_4G, PUBKEY_5G, PUBKEY_G, TestShareBlockBuilder, genesis_for_tests,
    setup_test_chain_store_handle,
};

/// Total confirmed shares to fill the window (MAX_PPLNS_WINDOW_SHARES).
const TOTAL_CONFIRMED_SHARES: usize = 133056;

/// Every Nth confirmed share references one uncle, yielding ~10% uncles.
const UNCLE_INTERVAL: usize = 10;

/// Base difficulty for benchmark shares.
const BASE_DIFFICULTY: u128 = 1024;

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

    let mut confirmed_shares: Vec<(BlockHash, String, u128, Vec<(String, u128)>)> =
        Vec::with_capacity(share_count);

    let mut uncle_counter: usize = 0;

    for share_index in 0..share_count {
        let miner_address = miner_addresses[share_index % miner_count].clone();
        let difficulty = BASE_DIFFICULTY + share_index as u128;
        let blockhash = blockhash_from_index(share_index);

        let uncle_data = if share_index % UNCLE_INTERVAL == 0 {
            let uncle_miner = miner_addresses[(uncle_counter + 2) % miner_count].clone();
            let uncle_difficulty = BASE_DIFFICULTY * 8 / 10;
            uncle_counter += 1;
            vec![(uncle_miner, uncle_difficulty)]
        } else {
            Vec::new()
        };

        confirmed_shares.push((blockhash, miner_address, difficulty, uncle_data));
    }

    eprintln!("  populated {} confirmed entries", confirmed_shares.len());

    let mut window = PplnsWindow::new(bitcoin::Network::Signet);
    window.populate_for_benchmark(confirmed_shares);
    window
}

fn bench_get_distribution(criterion: &mut Criterion) {
    let mut window = build_benchmark_window(TOTAL_CONFIRMED_SHARES);

    criterion.bench_function("get_distribution_full_window", |bencher| {
        bencher.iter(|| {
            black_box(window.get_distribution(u128::MAX));
        });
    });
}

criterion_group!(benches, bench_get_distribution);
criterion_main!(benches);
