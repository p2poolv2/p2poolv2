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

use crate::stratum::work::{coinbase::extract_outputs_from_coinbase2, tracker::JobTracker};
use bitcoin::Amount;
use std::sync::Arc;

/// Parse the coinbase in the latest job and return
pub fn get_distribution(
    tracker: &Arc<JobTracker>,
    pool_signature_length: usize,
    network: bitcoin::network::Network,
) -> Option<String> {
    let job_id = tracker.get_latest_job_id();
    let job_details = match tracker.get_job(job_id) {
        Some(job_details) => job_details,
        None => return None,
    };

    match extract_outputs_from_coinbase2(&job_details.coinbase2, pool_signature_length) {
        Ok(outputs) => {
            let total_value = job_details.blocktemplate.coinbasevalue;
            let mut exposition = String::new();

            // Use index in case the fees and donation addresses are
            // the same. This way we can leave on grafana how to show
            // them
            for (index, tx_out) in outputs.iter().enumerate() {
                if tx_out.value != Amount::ZERO {
                    match bitcoin::Address::from_script(&tx_out.script_pubkey, network) {
                        Ok(address) => {
                            exposition.push_str(&format!(
                                "coinbase_output{{index=\"{index}\",address=\"{address}\"}} {}\n",
                                tx_out.value.to_sat()
                            ));
                        }
                        Err(_) => tracing::error!("Error parsing address from coinbase"),
                    }
                }
            }

            exposition.push_str(&format!("coinbase_total {total_value}\n"));
            Some(exposition)
        }
        Err(e) => {
            tracing::error!("Failed to parse coinbase for metrics: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stratum::work::block_template::BlockTemplate;
    use crate::stratum::work::coinbase::parse_address;
    use crate::stratum::work::tracker::start_tracker_actor;
    use bitcoin::{Amount, Network, TxOut};
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;

    fn create_test_template() -> BlockTemplate {
        BlockTemplate {
            default_witness_commitment: None,
            height: 100,
            version: 0x20000000,
            previousblockhash: "0".repeat(64),
            bits: "1d00ffff".to_string(),
            curtime: 1234567890,
            transactions: vec![],
            coinbasevalue: 5_000_000_000,
            coinbaseaux: HashMap::new(),
            rules: vec![],
            vbavailable: HashMap::new(),
            vbrequired: 0,
            longpollid: "".to_string(),
            target: "".to_string(),
            mintime: 0,
            mutable: vec![],
            noncerange: "".to_string(),
            sigoplimit: 0,
            sizelimit: 0,
            weightlimit: 0,
        }
    }

    fn create_valid_coinbase2(pool_sig: &[u8], outputs: &[TxOut]) -> String {
        let mut coinbase2_bytes = Vec::new();
        coinbase2_bytes.push(pool_sig.len() as u8);
        coinbase2_bytes.extend_from_slice(pool_sig);
        coinbase2_bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // Sequence
        coinbase2_bytes.extend_from_slice(&bitcoin::consensus::serialize(&outputs.to_vec()));
        coinbase2_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // LockTime
        hex::encode(coinbase2_bytes)
    }

    #[tokio::test]
    async fn test_get_distribution_success() {
        let tracker = start_tracker_actor();

        let address = parse_address(
            "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d",
            Network::Signet,
        )
        .unwrap();

        let outputs = vec![TxOut {
            value: Amount::from_str("49 BTC").unwrap(),
            script_pubkey: address.script_pubkey(),
        }];

        let coinbase2 = create_valid_coinbase2(b"P2Poolv2", &outputs);

        let job_id = tracker.get_next_job_id();
        tracker.insert_job(
            Arc::new(create_test_template()),
            "".to_string(),
            coinbase2,
            None,
            job_id,
        );

        let result = get_distribution(&tracker, 8, Network::Signet);

        assert!(result.is_some());
        let exposition = result.unwrap();

        // only one ouput in exposition - skipping the witness commitment
        assert_eq!(exposition.matches("coinbase_output").count(), 1);

        assert!(exposition.contains(
            "coinbase_output{index=\"0\",address=\"tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d\"} 4900000000"
        ));
        assert!(exposition.contains("coinbase_total 5000000000"));
    }

    #[tokio::test]
    async fn test_get_distribution_no_jobs_returns_none() {
        let tracker = start_tracker_actor();

        // Don't insert any jobs
        let result = get_distribution(&tracker, 8, Network::Signet);

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_distribution_invalid_coinbase2_returns_none() {
        let tracker = start_tracker_actor();

        // Insert job with invalid coinbase2 (too short)
        let job_id = tracker.get_next_job_id();
        tracker.insert_job(
            Arc::new(create_test_template()),
            "".to_string(),
            "deadbeef".to_string(), // Invalid coinbase2
            None,
            job_id,
        );

        let result = get_distribution(&tracker, 8, Network::Signet);

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_distribution_multiple_outputs() {
        let tracker = start_tracker_actor();

        let addr1 = parse_address(
            "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d",
            Network::Signet,
        )
        .unwrap();
        let addr2 = parse_address(
            "tb1q0afww6y0kgl4tyjjyv6xlttvfwdfqxvrfzz35f",
            Network::Signet,
        )
        .unwrap();

        let outputs = vec![
            TxOut {
                value: Amount::from_str("48 BTC").unwrap(),
                script_pubkey: addr1.script_pubkey(),
            },
            TxOut {
                value: Amount::from_str("2 BTC").unwrap(),
                script_pubkey: addr2.script_pubkey(),
            },
        ];

        let coinbase2 = create_valid_coinbase2(b"P2Poolv2", &outputs);

        let job_id = tracker.get_next_job_id();
        tracker.insert_job(
            Arc::new(create_test_template()),
            "".to_string(),
            coinbase2,
            None,
            job_id,
        );

        let result = get_distribution(&tracker, 8, Network::Signet);

        assert!(result.is_some());
        let exposition = result.unwrap();
        assert!(exposition.contains(
            "coinbase_output{index=\"0\",address=\"tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d\"} 4800000000"
        ));
        assert!(exposition.contains(
            "coinbase_output{index=\"1\",address=\"tb1q0afww6y0kgl4tyjjyv6xlttvfwdfqxvrfzz35f\"} 200000000"
        ));
        assert!(exposition.contains("coinbase_total 5000000000"));
    }

    #[tokio::test]
    async fn test_get_distribution_unparseable_script_skips_output() {
        let tracker = start_tracker_actor();

        // Create an output with a valid address and one with an unparseable script
        let addr = parse_address(
            "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d",
            Network::Signet,
        )
        .unwrap();

        // OP_RETURN script - can't be converted to an address
        let op_return_script =
            bitcoin::ScriptBuf::from_bytes(vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]);

        let outputs = vec![
            TxOut {
                value: Amount::from_str("49 BTC").unwrap(),
                script_pubkey: addr.script_pubkey(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return_script,
            },
        ];

        let coinbase2 = create_valid_coinbase2(b"P2Poolv2", &outputs);

        let job_id = tracker.get_next_job_id();
        tracker.insert_job(
            Arc::new(create_test_template()),
            "".to_string(),
            coinbase2,
            None,
            job_id,
        );

        let result = get_distribution(&tracker, 8, Network::Signet);

        // Should still return Some, just without the unparseable output
        assert!(result.is_some());
        let exposition = result.unwrap();
        assert!(exposition.contains(
            "coinbase_output{index=\"0\",address=\"tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d\"} 4900000000"
        ));
        // OP_RETURN output should be skipped (no coinbase_output line for it)
        assert!(!exposition.contains("OP_RETURN"));
        assert!(exposition.contains("coinbase_total 5000000000"));
    }
}
