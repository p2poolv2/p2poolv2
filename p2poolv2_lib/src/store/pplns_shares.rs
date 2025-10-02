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

use super::{Store, column_families::ColumnFamily};
use crate::accounting::simple_pplns::SimplePplnsShare;
use std::time::{SystemTime, UNIX_EPOCH};

const INITIAL_SHARE_VEC_CAPACITY: usize = 100_000;

impl Store {
    /// Get PPLNS shares with filtering support using timestamp-based keys for efficient range queries
    /// Deserializes SimplePplnsShare from DB (btcaddress/workername are skipped during serialization)
    /// and enriches with btcaddress from user store
    pub fn get_pplns_shares_filtered(
        &self,
        limit: Option<usize>,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Vec<SimplePplnsShare> {
        let pplns_share_cf = self.db.cf_handle(&ColumnFamily::Share).unwrap();

        // Convert end_time to microseconds, default to current time if not specified
        let effective_end_time = end_time.map(|t| t * 1_000_000).unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64
        });

        let mut read_opts = rocksdb::ReadOptions::default();

        // Set lower bound for start_time if specified (exclusive lower bound)
        if let Some(start) = start_time {
            let start_micros = start * 1_000_000;
            // Create boundary key with minimum user_id and seq for lower bound
            let start_key = SimplePplnsShare::make_key(start_micros, 0, 0);
            read_opts.set_iterate_lower_bound(start_key);
        }

        // Create starting boundary key with maximum user_id and seq for reverse iteration
        let end_key = SimplePplnsShare::make_key(effective_end_time, u64::MAX, u64::MAX);

        let iter = self.db.iterator_cf_opt(
            pplns_share_cf,
            read_opts,
            rocksdb::IteratorMode::From(&end_key, rocksdb::Direction::Reverse),
        );

        let use_limit = limit.unwrap_or(INITIAL_SHARE_VEC_CAPACITY);
        let mut shares: Vec<SimplePplnsShare> = Vec::with_capacity(use_limit);

        for (_key, value) in iter.take(use_limit).flatten() {
            if let Ok(share) = ciborium::de::from_reader(&value[..]) {
                shares.push(share);
            }
        }

        self.populate_btcaddresses(&shares)
    }

    /// Populate the btcaddress for user_ids in the shares
    /// Uses get_btcaddresses_for_userids
    fn populate_btcaddresses(&self, shares: &[SimplePplnsShare]) -> Vec<SimplePplnsShare> {
        // Collect unique user_ids and query btcaddresses
        let user_ids: Vec<u64> = shares.iter().map(|s| s.user_id).collect();

        // Pass HashSet directly - no intermediate Vec allocation needed
        let btcaddress_map: std::collections::HashMap<u64, String> = self
            .get_btcaddresses_for_user_ids(&user_ids)
            .unwrap_or_default()
            .into_iter()
            .collect();

        // Populate btcaddress field (workername remains None as it's not stored)
        shares
            .iter()
            .filter_map(|share| {
                btcaddress_map.get(&share.user_id).map(|btcaddress| {
                    let mut enriched_share = share.clone();
                    enriched_share.btcaddress = Some(btcaddress.clone());
                    enriched_share
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use crate::store::Store;
    use tempfile::tempdir;

    #[test]
    fn test_get_pplns_shares_filtered_with_limit() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let user_id1 = store.add_user("addr1".to_string()).unwrap();
        let user_id2 = store.add_user("addr2".to_string()).unwrap();
        let user_id3 = store.add_user("addr3".to_string()).unwrap();

        // Add test shares with different timestamps
        let shares = vec![
            SimplePplnsShare::new(
                user_id1,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                1000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                user_id2,
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                2000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                user_id3,
                300,
                "addr3".to_string(),
                "worker3".to_string(),
                3000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        for share in &shares {
            store.add_pplns_share(share.clone()).unwrap();
        }

        // Test limit functionality
        let result = store.get_pplns_shares_filtered(Some(2), None, None);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_get_pplns_shares_filtered_with_time_range() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        let user_id1 = store.add_user("addr1".to_string()).unwrap();
        let user_id2 = store.add_user("addr2".to_string()).unwrap();
        let user_id3 = store.add_user("addr3".to_string()).unwrap();

        // Add test shares with different timestamps
        let shares = vec![
            SimplePplnsShare::new(
                user_id1,
                100,
                "addr1".to_string(),
                "worker1".to_string(),
                1000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                user_id2,
                200,
                "addr2".to_string(),
                "worker2".to_string(),
                2000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
            SimplePplnsShare::new(
                user_id3,
                300,
                "addr3".to_string(),
                "worker3".to_string(),
                3000,
                "job".to_string(),
                "extra".to_string(),
                "nonce".to_string(),
            ),
        ];

        for share in &shares {
            store.add_pplns_share(share.clone()).unwrap();
        }

        // Test time filtering
        let result = store.get_pplns_shares_filtered(Some(10), Some(1500), Some(2500));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].n_time, 2000);
    }
}
