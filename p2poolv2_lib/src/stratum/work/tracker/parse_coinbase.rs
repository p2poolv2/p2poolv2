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

use crate::stratum::work::{coinbase::extract_outputs_from_coinbase2, tracker::TrackerHandle};

/// Parse the coinbase in the latest job and return
pub async fn get_distribution(
    tracker: &TrackerHandle,
    pool_signature_length: usize,
    network: bitcoin::network::Network,
) -> Option<String> {
    let job_details = match tracker.get_latest_job_id().await {
        Ok(job_id) => match tracker.get_job(job_id).await.ok().flatten() {
            Some(job_details) => job_details,
            None => return None,
        },
        _ => return None,
    };

    match extract_outputs_from_coinbase2(&job_details.coinbase2, pool_signature_length) {
        Ok(outputs) => {
            let total_value = job_details.blocktemplate.coinbasevalue;
            let mut exposition = String::new();

            for tx_out in outputs.iter() {
                match bitcoin::Address::from_script(&tx_out.script_pubkey, network) {
                    Ok(address) => {
                        exposition.push_str(&format!(
                            "coinbase_output{{address=\"{address}\"}} {}\n",
                            tx_out.value.to_sat()
                        ));
                    }
                    Err(_) => tracing::error!("Error parsing address from coinbase"),
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
