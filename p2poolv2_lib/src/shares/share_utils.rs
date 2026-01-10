// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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
use crate::store::dag_store::DifficultyData;
/// Calculates the 10th and 90th percentile timestamps from difficulty data and the time delta between them.
/// # Arguments
/// * `difficulty_data` - A slice of DifficultyData containing timestamps and difficulty information
///
/// # Returns
/// A tuple containing:
/// * `u32` - The 10th percentile timestamp (filters out early outliers)
/// * `u32` - The 90th percentile timestamp (filters out late outliers)
/// * `u32` - The time delta between the two percentiles, used for difficulty calculations
///
/// # Example
/// ```
/// let (t10, t90, delta) = filter_timestamp_percentile_and_delta_t(&difficulty_data);
/// // delta represents the time span covering the middle 80% of blocks
/// ```
pub fn filter_timestamp_percentile_and_delta_t(difficulty_data: &[DifficultyData]) -> (u32, u32,u32) {
    if difficulty_data.is_empty() {
        return (0, 0,0);
    }
    let n = difficulty_data.len();

    // Calculate percentile indices
    let i_10 = ((n - 1) as f64 * 0.10).floor() as usize;
    let i_90 = ((n - 1) as f64 * 0.90).floor() as usize;

    // Extract timestamps into a mutable vector
    let mut timestamps: Vec<u32> = difficulty_data.iter().map(|d| d.time).collect();
    
    // First, partition to find 10th percentile
    timestamps.select_nth_unstable(i_10);
    let timestamp_10th = timestamps[i_10];

     // Then, partition to find 90th percentile
     timestamps.select_nth_unstable(i_90);
    let timestamp_90th = timestamps[i_90];
   
    let delta_t = calculate_time_delta(timestamp_10th,timestamp_90th,i_10,i_90);


     (timestamp_10th, timestamp_90th, delta_t)
}

pub fn calculate_time_delta(
    timestamp_10th: u32,
    timestamp_90th: u32,
    index1: usize,
    index2: usize,
) ->u32 {
    // Calculate index delta (number of blocks between percentiles)
    let delta_index = if index2 > index1 {
        (index2 - index1) as u32
    } else {
        1u32
    };

    // Calculate time delta with safety check
    let delta_t = if timestamp_90th > timestamp_10th + delta_index {
        timestamp_90th - timestamp_10th
    } else {
        delta_index
    };

    return delta_t;
}