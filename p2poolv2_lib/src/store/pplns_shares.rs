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

impl Store {
    /// Get PPLNS shares with filtering support using timestamp-based keys for efficient range queries
    pub fn get_pplns_shares_filtered(
        &self,
        limit: usize,
        start_time: Option<u64>,
        end_time: Option<u64>,
    ) -> Vec<SimplePplnsShare> {
        let pplns_share_cf = self.db.cf_handle(&ColumnFamily::Share).unwrap();

        // Use a simple approach with End iterator and filtering
        let mut iter = self
            .db
            .iterator_cf(pplns_share_cf, rocksdb::IteratorMode::End);
        let mut shares = Vec::new();
        let mut count = 0;

        while let Some(Ok((key, value))) = iter.next() {
            if count >= limit {
                break;
            }

            if filter_share_by_time(&key, start_time, end_time).is_some() {
                if let Ok(share) = ciborium::de::from_reader(&value[..]) {
                    shares.push(share);
                    count += 1;
                }
            }
        }

        shares
    }
}

fn filter_share_by_time(key: &[u8], start_time: Option<u64>, end_time: Option<u64>) -> Option<()> {
    let key_str = String::from_utf8_lossy(key);
    let timestamp_str = key_str.split(':').next()?;
    let timestamp_micros = timestamp_str.parse::<u64>().ok()?;
    let timestamp_secs = timestamp_micros / 1_000_000;

    if let Some(start) = start_time {
        if timestamp_secs < start {
            return None;
        }
    }

    if let Some(end) = end_time {
        if timestamp_secs > end {
            return None;
        }
    }

    Some(())
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

        // Add test shares with different timestamps
        let shares = vec![
            SimplePplnsShare::new(100, "addr1".to_string(), "worker1".to_string(), 1000),
            SimplePplnsShare::new(200, "addr2".to_string(), "worker2".to_string(), 2000),
            SimplePplnsShare::new(300, "addr3".to_string(), "worker3".to_string(), 3000),
        ];

        for share in &shares {
            store.add_pplns_share(share.clone()).unwrap();
        }

        // Test limit functionality
        let result = store.get_pplns_shares_filtered(2, None, None);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_get_pplns_shares_filtered_with_time_range() {
        let temp_dir = tempdir().unwrap();
        let store = Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap();

        // Add test shares with different timestamps
        let shares = vec![
            SimplePplnsShare::new(100, "addr1".to_string(), "worker1".to_string(), 1000),
            SimplePplnsShare::new(200, "addr2".to_string(), "worker2".to_string(), 2000),
            SimplePplnsShare::new(300, "addr3".to_string(), "worker3".to_string(), 3000),
        ];

        for share in &shares {
            store.add_pplns_share(share.clone()).unwrap();
        }

        // Test time filtering
        let result = store.get_pplns_shares_filtered(10, Some(1500), Some(2500));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].timestamp, 2000);
    }
}
