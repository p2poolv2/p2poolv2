// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Benchmark for grouping 210,000 (u64, u64) tuples by first element and
//! summing the second element per group.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const ELEMENT_COUNT: usize = 210_000;
const GROUP_COUNT: usize = 500;

fn bench_sum_u64(criterion: &mut Criterion) {
    let tuples: Vec<(u64, u64)> = (0..ELEMENT_COUNT as u64)
        .map(|index| (index % GROUP_COUNT as u64 + 1, index * 2))
        .collect();

    criterion.bench_function("group_by_sum_210k_u64_tuples", |bencher| {
        bencher.iter(|| {
            let mut grouped_sums = vec![0u64; GROUP_COUNT + 1];
            for (key, value) in black_box(&tuples) {
                grouped_sums[*key as usize] += value;
            }
            black_box(grouped_sums)
        });
    });
}

criterion_group!(benches, bench_sum_u64);
criterion_main!(benches);
