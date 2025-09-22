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

use super::coinbase::{build_coinbase_transaction, split_coinbase};
use super::error::WorkError;
use super::gbt::{BlockTemplate, build_merkle_branches_for_template};
use super::tracker::{JobId, TrackerHandle};
use crate::messages::{Notify, NotifyParams};
use crate::util::reverse_four_byte_chunks;
use crate::util::to_be_hex;
use bitcoin::script::PushBytesBuf;
use bitcoin::transaction::Version;
use p2poolv2_accounting::OutputPair;
use p2poolv2_accounting::simple_pplns::payout::{Payout, PplnsShareProvider};
use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::debug;

#[cfg(not(test))]
use crate::client_connections::ClientConnectionsHandle;
#[cfg(test)]
#[mockall_double::double]
use crate::client_connections::ClientConnectionsHandle;

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
async fn build_output_distribution<T>(template: &BlockTemplate, chain_handle: &T) -> Vec<OutputPair>
where
    T: PplnsShareProvider,
{
    // Create a Payout instance with reasonable defaults
    // TODO: These should be configurable
    let payout = Payout::new(2016, 86400); // 2016 blocks window, 1 day step size
    let total_amount = bitcoin::Amount::from_sat(template.coinbasevalue);

    // Use target difficulty from template as total difficulty for PPLNS
    // TODO: This should be calculated properly based on the PPLNS window
    // For now, use a reasonable default difficulty value
    let total_difficulty = 1000000u64; // Placeholder - should be calculated from actual pool difficulty

    match payout
        .get_output_distribution(chain_handle, total_difficulty, total_amount)
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

#[allow(dead_code)]
pub fn build_notify(
    template: &BlockTemplate,
    output_distribution: Vec<OutputPair>,
    job_id: JobId,
    clean_jobs: bool,
    _bootstrap_address: &bitcoin::Address,
) -> Result<Notify<'static>, WorkError> {
    let coinbase = build_coinbase_transaction(
        Version::TWO,
        output_distribution.as_slice(),
        template.height as i64,
        parse_flags(template.coinbaseaux.get("flags").cloned()),
        template.default_witness_commitment.clone(),
    )?;

    let (coinbase1, coinbase2) = split_coinbase(&coinbase)?;

    let merkle_branches = build_merkle_branches_for_template(template)
        .iter()
        .map(|branch| Cow::Owned(to_be_hex(&branch.to_string())))
        .collect::<Vec<_>>();

    let prevhash_byte_swapped =
        reverse_four_byte_chunks(&template.previousblockhash).map_err(|e| WorkError {
            message: format!("Failed to reverse previous block hash: {e}"),
        })?;

    let params = NotifyParams {
        job_id: Cow::Owned(format!("{job_id:016x}")),
        prevhash: Cow::Owned(prevhash_byte_swapped),
        coinbase1: Cow::Owned(coinbase1),
        coinbase2: Cow::Owned(coinbase2),
        merkle_branches,
        version: Cow::Owned(hex::encode(template.version.to_be_bytes())),
        nbits: Cow::Owned(template.bits.clone()),
        ntime: Cow::Owned(hex::encode(template.curtime.to_be_bytes())),
        clean_jobs,
    };

    Ok(Notify::new_notify(params))
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
pub async fn start_notify<T>(
    mut notifier_rx: mpsc::Receiver<NotifyCmd>,
    connections: ClientConnectionsHandle,
    pplns_provider: T,
    tracker_handle: TrackerHandle,
    bootstrap_address: bitcoin::Address,
) where
    T: PplnsShareProvider,
{
    let mut latest_template: Option<Arc<BlockTemplate>> = None;
    while let Some(cmd) = notifier_rx.recv().await {
        match cmd {
            NotifyCmd::SendToAll { template } => {
                let clean_jobs = latest_template.is_none()
                    || latest_template.unwrap().previousblockhash != template.previousblockhash;
                latest_template = Some(Arc::clone(&template));
                let job_id = tracker_handle.get_next_job_id().await.unwrap();
                let output_distribution =
                    build_output_distribution(&template, &pplns_provider).await;
                let notify_str = match build_notify(
                    &template,
                    output_distribution,
                    job_id,
                    clean_jobs,
                    &bootstrap_address,
                ) {
                    Ok(notify) => {
                        tracker_handle
                            .insert_job(
                                Arc::clone(&template),
                                notify.params.coinbase1.to_string(),
                                notify.params.coinbase2.to_string(),
                                job_id,
                            )
                            .await
                            .unwrap();

                        serde_json::to_string(&notify).expect("Failed to serialize Notify message")
                    }
                    Err(e) => {
                        debug!("Error building notify: {}", e);
                        continue; // Skip this iteration if notify cannot be built
                    }
                };
                connections.send_to_all(Arc::new(notify_str)).await;
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
                    continue; // Skip if no latest template is available
                }
                let job_id = tracker_handle.get_next_job_id().await.unwrap();
                let output_distribution =
                    build_output_distribution(latest_template.as_ref().unwrap(), &pplns_provider)
                        .await;
                let notify_str = match build_notify(
                    latest_template.as_ref().unwrap(),
                    output_distribution,
                    job_id,
                    clean_jobs,
                    &bootstrap_address,
                ) {
                    Ok(notify) => {
                        tracker_handle
                            .insert_job(
                                Arc::clone(latest_template.as_ref().unwrap()),
                                notify.params.coinbase1.to_string(),
                                notify.params.coinbase2.to_string(),
                                job_id,
                            )
                            .await
                            .unwrap();
                        serde_json::to_string(&notify).expect("Failed to serialize Notify message")
                    }
                    Err(e) => {
                        debug!("Error building notify: {}", e);
                        continue; // Skip this iteration if notify cannot be built
                    }
                };
                connections
                    .send_to_client(client_address, Arc::new(notify_str))
                    .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::difficulty_adjuster::DifficultyAdjuster;
    use crate::messages::{Response, SimpleRequest};
    use crate::session::Session;
    use crate::work::coinbase::parse_address;
    use crate::work::tracker::start_tracker_actor;
    use bitcoindrpc::test_utils::{mock_submit_block_with_any_body, setup_mock_bitcoin_rpc};
    use p2poolv2_accounting::simple_pplns::SimplePplnsShare;
    use p2poolv2_accounting::test_utils::MockPplnsShareProvider;
    use std::fs;
    use std::time::SystemTime;
    use tokio::sync::mpsc;

    #[test_log::test(tokio::test)]
    async fn test_build_notify_from_gbt_and_compare_to_expected() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json");
        let data = fs::read_to_string(path).expect("Unable to read file");
        let gbt_json: serde_json::Value = serde_json::from_str(&data).expect("Invalid JSON");

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/test_data/gbt/regtest/ckpool/one-txn/notify.json");
        let data = fs::read_to_string(path).expect("Unable to read file");
        let _notify_json: serde_json::Value = serde_json::from_str(&data).expect("Invalid JSON");

        // Parse BlockTemplate from GBT
        let template: BlockTemplate =
            serde_json::from_value(gbt_json.clone()).expect("Failed to parse BlockTemplate");

        // Address used in ckpool regtest conf
        let bootstrap_address = parse_address(
            "bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr",
            bitcoin::Network::Regtest,
        )
        .unwrap();

        let job_id = JobId(1);

        let timestamp = (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60)
            * 1_000_000;
        let mock_provider = MockPplnsShareProvider::new(vec![SimplePplnsShare {
            difficulty: 100,
            btcaddress: "bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr".to_string(),
            workername: "".to_string(),
            timestamp,
        }]);
        let output_distribution = build_output_distribution(&template, &mock_provider).await;
        // Build Notify
        let notify = build_notify(
            &template,
            output_distribution,
            job_id,
            false,
            &bootstrap_address,
        )
        .expect("Failed to build notify");

        // Compare all fields except job_id (random) coinbase which also have current time component
        assert_eq!(notify.params.version, "20000000");
        assert_eq!(notify.params.nbits, "207fffff");
        assert_eq!(notify.params.ntime, "68300262"); // we use curtime from gbt
        assert_eq!(notify.params.clean_jobs, false);
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
        let timestamp = (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60)
            * 1_000_000;
        let mock_provider = MockPplnsShareProvider::new(vec![SimplePplnsShare {
            difficulty: 100,
            btcaddress: "bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr".to_string(),
            workername: "".to_string(),
            timestamp,
        }]);

        // Start the notify task in a separate task
        let bootstrap_address = parse_address(
            "tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk",
            bitcoin::Network::Testnet,
        )
        .unwrap();
        let task_handle = tokio::spawn(async move {
            start_notify(
                notify_rx,
                mock_connections,
                mock_provider,
                work_map_handle,
                bootstrap_address,
            )
            .await;
        });

        // Load a sample block template
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json");
        let data = fs::read_to_string(path).expect("Unable to read file");
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

        // Cleanup
        drop(notify_tx); // Close the channel to terminate the task
        task_handle.await.expect("Task failed");
    }

    #[tokio::test]
    async fn test_build_notify_from_ckpool_sample() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let _tracker_handle = start_tracker_actor();

        let (mock_server, _bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let template_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/b/template.json"),
        )
        .unwrap();
        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();

        let notify_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/b/notify.json"),
        )
        .unwrap();
        let notify: Notify = serde_json::from_str(&notify_str).unwrap();

        let submit_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/b/submit.json"),
        )
        .unwrap();
        let _submit: SimpleRequest = serde_json::from_str(&submit_str).unwrap();

        let authorize_response_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/b/authorize_response.json"),
        )
        .unwrap();
        let authorize_response: Response = serde_json::from_str(&authorize_response_str).unwrap();

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();

        let job_id = u64::from_str_radix(&notify.params.job_id, 16).unwrap();
        let bootstrap_address = parse_address(
            "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d",
            bitcoin::Network::Signet,
        )
        .unwrap();
        let timestamp = (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 60)
            * 1_000_000;
        let mock_provider = MockPplnsShareProvider::new(vec![SimplePplnsShare {
            difficulty: 100,
            btcaddress: "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string(),
            workername: "".to_string(),
            timestamp,
        }]);
        let output_distribution = build_output_distribution(&template, &mock_provider).await;

        let result = build_notify(
            &template,
            output_distribution,
            JobId(job_id),
            false,
            &bootstrap_address,
        );

        assert_eq!(result.unwrap().params.prevhash, notify.params.prevhash);
    }
}
