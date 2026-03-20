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
use p2poolv2_lib::accounting::payout::sharechain_pplns::pplns_window::{
    PplnsWindow, UNCLE_WEIGHT_FACTOR, UncleEntry,
};
use p2poolv2_lib::shares::share_block::ShareHeader;
use p2poolv2_lib::test_utils::{
    PUBKEY_2G, PUBKEY_3G, PUBKEY_4G, PUBKEY_5G, PUBKEY_G, TestShareBlockBuilder,
};

/// Total confirmed shares to fill the window (MAX_PPLNS_WINDOW_SHARES).
const TOTAL_CONFIRMED_SHARES: usize = 120_960;

/// Every Nth confirmed share references one uncle, yielding ~10% uncles.
const UNCLE_INTERVAL: usize = 10;

/// Number of new shares for the incremental update benchmark.
const NEW_SHARES_FOR_UPDATE: usize = 960;

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

    let mut confirmed_shares: Vec<(BlockHash, String, f64, Vec<UncleEntry>)> =
        Vec::with_capacity(share_count);

    let mut uncle_counter: usize = 0;

    for share_index in 0..share_count {
        let miner_address = miner_addresses[share_index % miner_count].clone();
        let difficulty = BASE_DIFFICULTY + (share_index as f64) * 0.01;
        let blockhash = blockhash_from_index(share_index);

        let uncle_entries = if share_index % UNCLE_INTERVAL == 0 {
            let uncle_miner = miner_addresses[(uncle_counter + 2) % miner_count].clone();
            let uncle_difficulty = BASE_DIFFICULTY * 0.8;
            uncle_counter += 1;
            vec![UncleEntry {
                miner_address: uncle_miner,
                difficulty: uncle_difficulty,
            }]
        } else {
            Vec::new()
        };

        confirmed_shares.push((blockhash, miner_address, difficulty, uncle_entries));
    }

    let mut window = PplnsWindow::default();
    window.populate_for_benchmark(confirmed_shares);
    window
}

/// Build a chain of new ShareHeaders for the update benchmark.
///
/// Returns confirmed headers in newest-to-oldest order (matching chain store
/// convention) plus uncle headers.
fn build_new_headers_for_update(
    count: usize,
    start_prev_hash: &str,
) -> (Vec<(BlockHash, ShareHeader)>, Vec<(BlockHash, ShareHeader)>) {
    let mut confirmed_headers: Vec<(BlockHash, ShareHeader)> = Vec::with_capacity(count);
    let mut uncle_headers: Vec<(BlockHash, ShareHeader)> = Vec::new();
    let mut prev_hash = start_prev_hash.to_string();

    for index in 0..count {
        let pubkey = MINER_PUBKEYS[index % MINER_PUBKEYS.len()];

        // Every UNCLE_INTERVAL shares, create an uncle
        let (uncles_for_share, uncle_header_entry) = if index % UNCLE_INTERVAL == 0 {
            let uncle_pubkey = MINER_PUBKEYS[(index + 2) % MINER_PUBKEYS.len()];
            let uncle_header = TestShareBlockBuilder::new()
                .prev_share_blockhash(prev_hash.clone())
                .miner_pubkey(uncle_pubkey)
                .work(2)
                .build()
                .header;
            let uncle_blockhash = uncle_header.block_hash();
            (vec![uncle_blockhash], Some((uncle_blockhash, uncle_header)))
        } else {
            (Vec::new(), None)
        };

        let header = TestShareBlockBuilder::new()
            .prev_share_blockhash(prev_hash)
            .miner_pubkey(pubkey)
            .work(2)
            .uncles(uncles_for_share)
            .build()
            .header;
        let blockhash = header.block_hash();
        prev_hash = blockhash.to_string();
        confirmed_headers.push((blockhash, header));

        if let Some(uncle_entry) = uncle_header_entry {
            uncle_headers.push(uncle_entry);
        }
    }

    // Reverse to newest-to-oldest (chain store convention)
    confirmed_headers.reverse();
    (confirmed_headers, uncle_headers)
}

fn bench_get_address_difficulty_map(criterion: &mut Criterion) {
    let window = build_benchmark_window(TOTAL_CONFIRMED_SHARES);

    criterion.bench_function("get_address_difficulty_map_full_window", |bencher| {
        bencher.iter(|| {
            black_box(window.get_address_difficulty_map());
        });
    });
}

fn bench_update(criterion: &mut Criterion) {
    let prefill_count = TOTAL_CONFIRMED_SHARES - NEW_SHARES_FOR_UPDATE;
    let prev_hash = blockhash_from_index(prefill_count - 1).to_string();
    let (new_confirmed_headers, new_uncle_headers) =
        build_new_headers_for_update(NEW_SHARES_FOR_UPDATE, &prev_hash);

    criterion.bench_function("update_incremental", |bencher| {
        let confirmed_clone = new_confirmed_headers.clone();
        let uncle_clone = new_uncle_headers.clone();

        bencher.iter_batched(
            || {
                let window = build_benchmark_window(prefill_count);
                (window, confirmed_clone.clone(), uncle_clone.clone())
            },
            |(mut window, confirmed_headers, uncle_headers)| {
                black_box(window.load_entries_for_benchmark(
                    confirmed_headers,
                    uncle_headers,
                    f64::MAX,
                ));
            },
            criterion::BatchSize::LargeInput,
        );
    });
}

criterion_group!(benches, bench_get_address_difficulty_map, bench_update);
criterion_main!(benches);
