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

use crate::store::{ColumnFamily, Store};
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

impl Store {
    /// Save a job with the given timestamp key to the Job column family
    pub fn add_job(
        &self,
        timestamp: u64,
        serialized_notify: String,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        debug!("Saving job to store with key: {:?}", timestamp);
        let job_cf = self.db.cf_handle(&ColumnFamily::Job).unwrap();
        self.db.put_cf(
            &job_cf,
            timestamp.to_be_bytes(),
            serialized_notify.as_bytes(),
        )?;
        Ok(())
    }

    /// Get jobs within a time range from the Job column family
    /// Returns jobs ordered by timestamp (newest first)
    pub fn get_jobs(
        &self,
        start_time: Option<u64>,
        end_time: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(u64, String)>, Box<dyn Error + Send + Sync>> {
        debug!(
            "Getting jobs from store with start_time: {:?}, end_time: {:?}, limit: {}",
            start_time, end_time, limit
        );

        let job_cf = self.db.cf_handle(&ColumnFamily::Job).unwrap();

        // If end_time is None, use current time
        let effective_end_time = end_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64
        });

        // Create a read options object to set iteration bounds
        let mut read_opts = rocksdb::ReadOptions::default();

        if let Some(start) = start_time {
            // Set the lower bound (start_time) for reverse iteration
            read_opts.set_iterate_lower_bound(start.to_be_bytes().to_vec());
        }

        // Start iterating from end_time in reverse order to get newest first
        let iter = self.db.iterator_cf_opt(
            &job_cf,
            read_opts,
            rocksdb::IteratorMode::From(
                &effective_end_time.to_be_bytes(),
                rocksdb::Direction::Reverse,
            ),
        );

        // Collect results
        let mut results = Vec::with_capacity(limit);

        for (i, item) in iter.enumerate() {
            if i >= limit {
                break;
            }

            let (key, value) = item?;

            // Convert key bytes to u64 timestamp
            let timestamp = u64::from_be_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| "Invalid timestamp key")?,
            );

            // Convert value bytes to string
            let job_data =
                String::from_utf8(value.to_vec()).map_err(|e| format!("Invalid job data: {e}"))?;

            results.push((timestamp, job_data));
        }

        Ok(results)
    }
}
