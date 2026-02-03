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

use super::block_template::BlockTemplate;
use super::coinbase::{build_coinbase_transaction, split_coinbase};
use super::error::WorkError;
use super::gbt::build_merkle_branches_for_template;
use super::tracker::{JobId, JobTracker};
use crate::accounting::OutputPair;
use crate::accounting::simple_pplns::payout::Payout;
use crate::config::StratumConfig;
#[cfg(test)]
#[mockall_double::double]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
#[cfg(not(test))]
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::shares::share_commitment::{ShareCommitment, build_share_commitment};
use crate::stratum::messages::{Notify, NotifyParams};
use crate::stratum::util::reverse_four_byte_chunks;
use crate::stratum::util::to_be_hex;
use bitcoin::CompressedPublicKey;
use bitcoin::script::PushBytesBuf;
use bitcoin::transaction::Version;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::debug;

#[cfg(not(test))]
use crate::stratum::client_connections::ClientConnectionsHandle;
#[cfg(test)]
#[mockall_double::double]
use crate::stratum::client_connections::ClientConnectionsHandle;

/// Extract flags from template coinbaseaux and convert to PushBytesBuf
/// If flags are empty, use a single byte with value 0
#[allow(dead_code)]
fn parse_flags(flags: Option<String>) -> PushBytesBuf {
    match flags {
        Some(flags) if flags.is_empty() => PushBytesBuf::from(&[0u8]),
        Some(flags) => PushBytesBuf::try_from(hex::decode(flags).unwrap()).unwrap(),
        None => PushBytesBuf::from(&[0u8]),
    }
}

/// Build the output distribution for the coinbase transaction using PPLNS accounting.
///
/// difficulty_multiplier is used to get the total difficulty we need
/// to match to collect all the shares to use to compute output distribution.
async fn build_output_distribution(
    template: &BlockTemplate,
    chain_store_handle: &ChainStoreHandle,
    config: &StratumConfig<crate::config::Parsed>,
) -> Vec<OutputPair> {
    const DEFAULT_STEP_SIZE_SECONDS: u64 = 24 * 60 * 60; // 1 day
    let payout = Payout::new(DEFAULT_STEP_SIZE_SECONDS);
    let total_amount = bitcoin::Amount::from_sat(template.coinbasevalue);

    let compact_target = bitcoin::pow::CompactTarget::from_unprefixed_hex(&template.bits).unwrap();
    let required_target = bitcoin::Target::from_compact(compact_target);

    let total_difficulty = required_target.difficulty_float() * config.difficulty_multiplier;

    match payout
        .get_output_distribution(chain_store_handle, total_difficulty, total_amount, config)
        .await
    {
        Ok(distribution) => distribution,
        Err(e) => {
            // Log error and return empty distribution
            debug!("PPLNS accounting failed: {}", e);
            Vec::new()
        }
    }
}

pub fn build_notify(
    template: &BlockTemplate,
    output_distribution: Vec<OutputPair>,
    job_id: JobId,
    clean_jobs: bool,
    pool_signature: &[u8],
    commitment_hash: Option<bitcoin::hashes::sha256::Hash>,
) -> Result<Notify, WorkError> {
    let coinbase = build_coinbase_transaction(
        Version::TWO,
        output_distribution.as_slice(),
        template.height as i64,
        parse_flags(template.coinbaseaux.get("flags").cloned()),
        template.default_witness_commitment.clone(),
        pool_signature,
        commitment_hash,
    )?;

    let (coinbase1, coinbase2) = split_coinbase(&coinbase)?;

    let merkle_branches = build_merkle_branches_for_template(template)
        .iter()
        .map(|branch| to_be_hex(&branch.to_string()))
        .collect::<Vec<_>>();

    let prevhash_byte_swapped =
        reverse_four_byte_chunks(&template.previousblockhash).map_err(|e| WorkError {
            message: format!("Failed to reverse previous block hash: {e}"),
        })?;

    let params = NotifyParams {
        job_id: format!("{job_id:016x}"),
        prevhash: prevhash_byte_swapped,
        coinbase1,
        coinbase2,
        merkle_branches,
        version: hex::encode(template.version.to_be_bytes()),
        nbits: template.bits.clone(),
        ntime: hex::encode(template.curtime.to_be_bytes()),
        clean_jobs,
    };

    Ok(Notify::new_notify(params))
}

/// Helper function to build notify, build share commitment and insert
/// job into tracker. We need to do all this for SendToAll and
/// SendToClient. So we DRY it here.
///
/// Returns the serialized notify string on success.
async fn build_notify_and_commitment(
    template: &Arc<BlockTemplate>,
    clean_jobs: bool,
    chain_store_handle: &ChainStoreHandle,
    config: &StratumConfig<crate::config::Parsed>,
    miner_pubkey: Option<CompressedPublicKey>,
    pool_signature: &[u8],
    tracker_handle: &Arc<JobTracker>,
) -> Result<(String, Option<ShareCommitment>), WorkError> {
    let job_id = tracker_handle.get_next_job_id();
    let output_distribution = build_output_distribution(template, chain_store_handle, config).await;

    let share_commitment = build_share_commitment(chain_store_handle, template, miner_pubkey)
        .map_err(|_| WorkError {
            message: "Failed to build share commitment".to_string(),
        })?;
    let commitment_hash = share_commitment
        .as_ref()
        .map(|commitment| commitment.hash());

    let notify = build_notify(
        template,
        output_distribution,
        job_id,
        clean_jobs,
        pool_signature,
        commitment_hash,
    )?;

    let serialized_notify =
        serde_json::to_string(&notify).expect("Failed to serialize Notify message");

    tracker_handle.insert_job(
        Arc::clone(template),
        notify.params.coinbase1.to_string(),
        notify.params.coinbase2.to_string(),
        share_commitment.clone(),
        job_id,
    );

    Ok((serialized_notify, share_commitment))
}

/// NotifyCmd is used to send notify to all clients or a single client.
pub enum NotifyCmd {
    SendToAll {
        /// The block template to notify clients about.
        template: Arc<BlockTemplate>,
    },
    SendToClient {
        /// The address of the client to notify, if None, notify all clients.
        /// The latest template is used for the notify, so there is not template here.
        client_address: SocketAddr,
        clean_jobs: bool,
    },
}

/// Start a task that listens for new block template events.
/// As new templates arrives, the tasks build new Notify messages and sends them to all connected clients.
pub async fn start_notify(
    mut notifier_rx: mpsc::Receiver<NotifyCmd>,
    connections: ClientConnectionsHandle,
    chain_store_handle: ChainStoreHandle,
    tracker_handle: Arc<JobTracker>,
    config: &StratumConfig<crate::config::Parsed>,
    miner_pubkey: Option<CompressedPublicKey>,
) {
    let mut latest_template: Option<Arc<BlockTemplate>> = None;
    let pool_signature = match config.pool_signature {
        Some(ref sig) => sig.as_bytes(),
        None => &[],
    };

    while let Some(cmd) = notifier_rx.recv().await {
        match cmd {
            NotifyCmd::SendToAll { template } => {
                let clean_jobs = latest_template.is_none()
                    || latest_template.unwrap().previousblockhash != template.previousblockhash;
                latest_template = Some(Arc::clone(&template));

                let (notify_str, _share_commitment) = match build_notify_and_commitment(
                    &template,
                    clean_jobs,
                    &chain_store_handle,
                    config,
                    miner_pubkey,
                    pool_signature,
                    &tracker_handle,
                )
                .await
                {
                    Ok(serialized) => serialized,
                    Err(e) => {
                        tracing::error!("Failed to build notify: {}. Skipping.", e);
                        continue;
                    }
                };

                connections.send_to_all(Arc::new(notify_str.clone())).await;
                if chain_store_handle.add_job(notify_str).await.is_err() {
                    tracing::warn!("Couldn't save job when sending to all");
                }
            }
            NotifyCmd::SendToClient {
                client_address,
                clean_jobs,
            } => {
                if latest_template.is_none() {
                    debug!(
                        "No latest template available to send to client: {}",
                        client_address
                    );
                    continue;
                }

                let template = latest_template.as_ref().unwrap();
                let (notify_str, _share_commitment) = match build_notify_and_commitment(
                    template,
                    clean_jobs,
                    &chain_store_handle,
                    config,
                    miner_pubkey,
                    pool_signature,
                    &tracker_handle,
                )
                .await
                {
                    Ok(serialized) => serialized,
                    Err(e) => {
                        tracing::error!("Failed to build notify: {}. Skipping.", e);
                        continue;
                    }
                };

                connections
                    .send_to_client(client_address, Arc::new(notify_str.clone()))
                    .await;
                if chain_store_handle.add_job(notify_str).await.is_err() {
                    tracing::warn!("Couldn't save job when sending to client");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use crate::stratum::work::block_template::{BlockTemplate, TemplateTransaction};
    use crate::stratum::work::coinbase::extract_outputs_from_coinbase2;
    use crate::stratum::work::tracker::start_tracker_actor;
    use crate::test_utils::genesis_for_tests;
    use bitcoin::CompressedPublicKey;
    use bitcoin::{Amount, ScriptBuf, TxOut};
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::time::SystemTime;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_build_notify_from_gbt_and_compare_to_expected() {
        let data = include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        );
        let gbt_json: serde_json::Value = serde_json::from_str(&data).expect("Invalid JSON");

        let data = include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/notify.json"
        );
        let _notify_json: serde_json::Value = serde_json::from_str(&data).expect("Invalid JSON");

        // Parse BlockTemplate from GBT
        let template: BlockTemplate =
            serde_json::from_value(gbt_json.clone()).expect("Failed to parse BlockTemplate");

        let job_id = JobId(1);

        let n_time = (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60)
            * 1_000_000;

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![SimplePplnsShare {
            user_id: 1,
            difficulty: 100,
            btcaddress: Some("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr".to_string()),
            workername: Some("".to_string()),
            n_time,
            job_id: "test_job".to_string(),
            extranonce2: "test_extra".to_string(),
            nonce: "test_nonce".to_string(),
        }];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let stratum_config = StratumConfig::default().parse().unwrap();

        let output_distribution =
            build_output_distribution(&template, &chain_store_handle, &stratum_config).await;
        // Build Notify
        let notify = build_notify(&template, output_distribution, job_id, false, &[], None)
            .expect("Failed to build notify");

        // Compare all fields except job_id (random) coinbase which also have current time component
        assert_eq!(notify.params.version, "20000000");
        assert_eq!(notify.params.nbits, "207fffff");
        assert_eq!(notify.params.ntime, "68300262"); // we use curtime from gbt
        assert!(!notify.params.clean_jobs);
        assert_eq!(
            notify.params.prevhash,
            "aadbdeb0c770ef1cc9115a42aa0a34e91732c422c0cd7ddbe71b3d9145f85fa6"
        );

        // TODO: Mock current time so we can compare coinbase1 and coinbase2
        // // assert_eq!(notify.params.coinbase1, expected_notify.params.coinbase1);
        // // assert_eq!(notify.params.coinbase2, expected_notify.params.coinbase2);
        assert_eq!(
            notify.params.merkle_branches,
            vec!["fecdf8cf1147587b0b3a262b16a955849053c6dfe0239718559f6a3d3ed20523".to_string()]
        );
    }

    #[test]
    fn test_parse_flags() {
        // Test with empty string
        let flags = parse_flags(Some(String::from("")));
        assert_eq!(flags.as_bytes(), &[0u8]);

        // Test with None
        let flags = parse_flags(None);
        assert_eq!(flags.as_bytes(), &[0u8]);

        // Test with valid hex string
        let flags = parse_flags(Some(String::from("deadbeef")));
        assert_eq!(flags.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[tokio::test]
    async fn test_start_notify() {
        // Set up mock connections
        let mut mock_connections = ClientConnectionsHandle::default();

        // Set up expectations
        mock_connections
            .expect_send_to_all()
            .times(1)
            .returning(|_| ());
        mock_connections
            .expect_send_to_client()
            .times(1)
            .returning(|_, _| true);

        // Create a channel for block template notifications
        let (notify_tx, notify_rx) = mpsc::channel::<NotifyCmd>(10);

        let work_map_handle = start_tracker_actor();

        // Setup mock PPLNS provider
        let n_time = (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60)
            * 1_000_000;

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![SimplePplnsShare {
            user_id: 1,
            difficulty: 100,
            btcaddress: Some("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr".to_string()),
            workername: Some("".to_string()),
            n_time,
            job_id: "test_job".to_string(),
            extranonce2: "test_extra".to_string(),
            nonce: "test_nonce".to_string(),
        }];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        chain_store_handle.expect_add_job().returning(|_| Ok(()));

        chain_store_handle
            .expect_get_current_target()
            .returning(|| Ok(503543726));

        let genesis = genesis_for_tests().block_hash();
        chain_store_handle
            .expect_get_chain_tip_and_uncles()
            .returning(move || (genesis, std::collections::HashSet::new()));

        let stratum_config = StratumConfig::default().parse().unwrap();
        let miner_pubkey: CompressedPublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();

        let task_handle = tokio::spawn(async move {
            start_notify(
                notify_rx,
                mock_connections,
                chain_store_handle,
                work_map_handle,
                &stratum_config,
                Some(miner_pubkey),
            )
            .await;
        });

        // Load a sample block template
        let data = include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        );
        let gbt_json: serde_json::Value = serde_json::from_str(&data).expect("Invalid JSON");
        let template: BlockTemplate =
            serde_json::from_value(gbt_json.clone()).expect("Failed to parse BlockTemplate");

        // Send the template through the channel
        notify_tx
            .send(NotifyCmd::SendToAll {
                template: Arc::new(template),
            })
            .await
            .expect("Failed to send template");

        // Give some time for the message to be processed
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        notify_tx
            .send(NotifyCmd::SendToClient {
                client_address: SocketAddr::from(([127, 0, 0, 1], 8080)), // dummy client address, mock client connections won't use this.
                clean_jobs: false,
            })
            .await
            .expect("Failed to send template to client");

        // Give some time for the message to be processed
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Cleanup
        drop(notify_tx); // Close the channel to terminate the task
        task_handle.await.expect("Task failed");
    }

    #[tokio::test]
    async fn test_build_notify_and_commitment() {
        // Load a sample block template
        let data = include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        );
        let gbt_json: serde_json::Value = serde_json::from_str(&data).expect("Invalid JSON");
        let template: BlockTemplate =
            serde_json::from_value(gbt_json.clone()).expect("Failed to parse BlockTemplate");

        // Setup mock chain store
        let n_time = (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60)
            * 1_000_000;

        let mut chain_store_handle = ChainStoreHandle::default();

        let shares = vec![SimplePplnsShare {
            user_id: 1,
            difficulty: 100,
            btcaddress: Some("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr".to_string()),
            workername: Some("".to_string()),
            n_time,
            job_id: "test_job".to_string(),
            extranonce2: "test_extra".to_string(),
            nonce: "test_nonce".to_string(),
        }];

        chain_store_handle
            .expect_get_pplns_shares_filtered()
            .return_const(shares);

        let genesis = genesis_for_tests().block_hash();
        chain_store_handle
            .expect_get_chain_tip_and_uncles()
            .returning(move || (genesis, std::collections::HashSet::new()));

        chain_store_handle
            .expect_get_current_target()
            .returning(|| Ok(503543726));

        // Setup config and tracker
        let stratum_config = StratumConfig::default().parse().unwrap();
        let tracker_handle = start_tracker_actor();
        let miner_pubkey: CompressedPublicKey =
            "020202020202020202020202020202020202020202020202020202020202020202"
                .parse()
                .unwrap();
        let pool_signature = b"test_pool";

        // Call build_notify_and_commitment
        let result = build_notify_and_commitment(
            &Arc::new(template.clone()),
            false,
            &chain_store_handle,
            &stratum_config,
            Some(miner_pubkey),
            pool_signature,
            &tracker_handle,
        )
        .await;

        // Verify the result
        assert!(result.is_ok());
        let (notify_str, share_commitment) = result.unwrap();

        // Verify notify string is valid JSON
        let notify: Notify = serde_json::from_str(&notify_str).expect("Invalid notify JSON");
        assert_eq!(notify.params.version, "20000000");
        assert_eq!(notify.params.nbits, "207fffff");
        assert!(!notify.params.clean_jobs);

        // Verify share commitment was created
        assert!(share_commitment.is_some());
        let commitment = share_commitment.unwrap();
        assert_eq!(commitment.miner_pubkey, miner_pubkey);

        // Verify the job was inserted in the tracker
        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());
        let job_details = tracker_handle.get_job(job_id);
        assert!(job_details.is_some());
        let details = job_details.unwrap();

        // Verify share_commitment is properly set in tracker
        assert!(details.share_commitment.is_some());
        let stored_commitment = details.share_commitment.unwrap();
        assert_eq!(stored_commitment.miner_pubkey, miner_pubkey);
        assert_eq!(stored_commitment.prev_share_blockhash, genesis);
    }

    /// This test build_notify, parse then verify
    #[tokio::test]
    async fn test_build_notify_and_extract_outputs_integration() {
        let template = BlockTemplate {
            default_witness_commitment: Some(
                "6a24aa21a9ed010000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            ),
            height: 100,
            version: 0x20000000,
            previousblockhash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            bits: "1d00ffff".to_string(),
            curtime: 1234567890,
            transactions: vec![TemplateTransaction {
                data: "".to_string(),
                txid: "0000000000000000000000000000000000000000000000000000000000000001"
                    .to_string(),
                hash: "".to_string(),
                depends: vec![],
                fee: 0,
                sigops: 0,
                weight: 0,
            }],
            coinbasevalue: 100000,
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
        };

        // We use OutputPair from accounting, but need to convert to TxOut for the check
        let original_output_pairs = vec![
            OutputPair {
                address: bitcoin::Address::from_str("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr")
                    .unwrap()
                    .assume_checked(),
                amount: Amount::from_sat(50000),
            },
            OutputPair {
                address: bitcoin::Address::from_str("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf")
                    .unwrap()
                    .assume_checked(),
                amount: Amount::from_sat(12345),
            },
        ];

        let job_id = JobId(123);
        let pool_signature = b"test_sig";

        // Generate the real `coinbase2`
        let notify = build_notify(
            &template,
            original_output_pairs.clone(),
            job_id,
            true,
            pool_signature,
            None, // No commitment hash
        )
        .unwrap();

        let coinbase2_hex = &notify.params.coinbase2;

        // Run the parser
        let extracted_txouts =
            extract_outputs_from_coinbase2(coinbase2_hex, pool_signature.len()).unwrap();

        // Verify: Check if the extracted data matches the original

        // We must check against the *real* outputs, which includes the witness
        let expected_txout_1 = TxOut {
            value: original_output_pairs[0].amount,
            script_pubkey: original_output_pairs[0].address.script_pubkey(),
        };
        let expected_txout_2 = TxOut {
            value: original_output_pairs[1].amount,
            script_pubkey: original_output_pairs[1].address.script_pubkey(),
        };

        let witness_script =
            ScriptBuf::from(hex::decode(template.default_witness_commitment.unwrap()).unwrap());
        let expected_txout_3 = TxOut {
            value: Amount::ZERO,
            script_pubkey: witness_script,
        };

        assert_eq!(extracted_txouts.len(), 3); // 2 payments + 1 witness
        assert_eq!(extracted_txouts[0], expected_txout_1);
        assert_eq!(extracted_txouts[1], expected_txout_2);
        assert_eq!(extracted_txouts[2], expected_txout_3);
    }
}
