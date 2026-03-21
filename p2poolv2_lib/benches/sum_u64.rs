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

//! Benchmark for grouping 210,000 (u64, u64) tuples by first element and
//! summing the second element per group.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

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
