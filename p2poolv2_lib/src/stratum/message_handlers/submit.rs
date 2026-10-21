// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::accounting::payout::simple_pplns::SimplePplnsShare;
use crate::config::PoolMode;
use crate::shares::coinbase_proof::CoinbaseProof;
use crate::stratum::{
    difficulty_adjuster::DifficultyAdjusterTrait,
    emission::Emission,
    error::{Error, StratumErrorCode},
    messages::{Message, Response, SetDifficultyNotification, SimpleRequest},
    server::StratumContext,
    session::Session,
    work::{
        block_template::BlockTemplate, difficulty::validate::validate_bitcoin_difficulty,
        tracker::JobId,
    },
};
use bitcoin::{block::Header, blockdata::block::Block, hashes::Hash};
use bitcoindrpc::BitcoindRpcClient;
use serde_json::json;
use std::time::SystemTime;
use tracing::{debug, error, info};

/// Handle the "mining.submit" message
/// This function is called when a miner submits a share to the Stratum server.
/// It sends a response with the submission status.
///
/// Message format:
///
/// {"id": 1, "method": "mining.submit", "params": ["username", "jobid", "extranonce2", "nTime", "nonce"]}
/// Example message:
/// {"id": 1, "method": "mining.submit", "params": ["username", "4f", "fe36a31b", "504e86ed", "e9695791"]}
/// We can also receive messages with version_mask as the last parameter
/// {"id": 1, "method": "mining.submit", "params": ["username", "jobid", "extranonce2", "nTime", "nonce", "version_mask"]}
/// Example message:
/// {"id": 1, "method": "mining.submit", "params": ["username", "4f", "fe36a31b", "504e86ed", "e9695791", "1fffe000"]}
///
/// Handling version mask, we check mask is valid and then apply it to the block header
///
/// Where an accepted share goes depends on the pool mode. In P2Poolv2 mode a
/// share meeting the pool target is emitted to the share chain. In Hydrapool
/// mode a share whose hash meets the session difficulty is queued for the PPLNS
/// share worker; it is never emitted.
pub(crate) async fn handle_submit<'a, D: DifficultyAdjusterTrait>(
    message: SimpleRequest<'a>,
    session: &mut Session<D>,
    stratum_context: StratumContext,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.submit message");
    if !session.subscribed {
        return Ok(vec![Message::Response(Response::new_error(
            message.id,
            StratumErrorCode::NotSubscribed,
        ))]);
    }
    if session.user_id.is_none() {
        return Ok(vec![Message::Response(
            Response::new_error(message.id, StratumErrorCode::UnauthorizedWorker)
                .with_message("Not authorized".to_string()),
        )]);
    }
    if message.params.len() < 5 {
        return Err(Error::InvalidParams("Missing parameters".into()));
    }

    let id = message.params[1]
        .as_ref()
        .ok_or_else(|| Error::InvalidParams("Missing job_id".into()))?;

    let job_id =
        u64::from_str_radix(id, 16).map_err(|_| Error::InvalidParams("Invalid job_id".into()))?;

    let job = match stratum_context.tracker_handle.get_job(JobId(job_id)) {
        Some(job) => job,
        None => {
            debug!("Job not found for job_id: {job_id}");
            return Ok(vec![Message::Response(Response::new_error(
                message.id,
                StratumErrorCode::JobNotFound,
            ))]);
        }
    };

    let current_difficulty = session.difficulty_adjuster.get_current_difficulty();

    // version mask from the session - we ignore different version mask sent in a submit message
    let version_mask = session.version_mask;

    // Validate the difficulty of the submitted share
    let validation_result =
        match validate_bitcoin_difficulty(&job, &message, &session.enonce1_hex, version_mask) {
            Ok(result) => result,
            Err(e) => {
                debug!("Share validation failed: {}", e);
                let response = Response::new_error(message.id, StratumErrorCode::OtherUnknown)
                    .with_message(e.to_string());
                return Ok(vec![Message::Response(response)]);
            }
        };

    // Compute the block hash once; it is reused for dedup, the pool-target
    // check, and the true-difficulty calculation on this hot path.
    let block_hash = validation_result.header.block_hash();

    let is_new_share = stratum_context
        .tracker_handle
        .add_share(JobId(job_id), block_hash);

    if !is_new_share {
        return Ok(vec![Message::Response(Response::new_error(
            message.id,
            StratumErrorCode::DuplicateShare,
        ))]);
    }

    // Under the `sim` feature, never auto-submit a bitcoin block from a stratum
    // share: on regtest a random header meets the bitcoin target ~50% of the
    // time, so this would spam spurious block submissions and (via the
    // confirmation -> re-notify loop) distort the measured uncle rate. Real
    // block-finds in the load test go only through the statistical block-find
    // path. See docs/simulation/load-test-plan.md.
    #[cfg(not(feature = "sim"))]
    if validation_result.meets_bitcoin_difficulty {
        // Submit block asap - decode transactions only for this rare case
        let block = build_full_block(
            validation_result.header,
            validation_result.coinbase.clone(),
            &job.blocktemplate,
        );
        submit_block(&block, &stratum_context.bitcoindrpc_client).await;
    }

    // Mining difficulties are tracked as `truediffone`, i.e. difficulty is computed relative to mainnet
    let truediff = get_true_difficulty(&block_hash);
    debug!("True difficulty: {}", truediff);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // params[2] (extranonce2) and params[4] (nonce) are guaranteed present
    // because validate_bitcoin_difficulty already validated them above.
    let extranonce2 = message.params[2]
        .as_ref()
        .expect("validated by validate_bitcoin_difficulty");
    let nonce = message.params[4]
        .as_ref()
        .expect("validated by validate_bitcoin_difficulty");
    let stratum_share = SimplePplnsShare::new(
        session.user_id.unwrap(),
        current_difficulty,
        session.btcaddress.clone().unwrap_or_default(),
        session.workername.clone().unwrap_or_default(),
        timestamp,
        id.to_string(),
        extranonce2.to_string(),
        nonce.to_string(),
    );

    // The hash proves work only up to `truediff`. A share is credited at the
    // session difficulty, so it may only be stored when its hash meets that
    // difficulty. `ignore_difficulty` is a testing aid for the miner response
    // and metrics below; it must never open this gate.
    let hash_meets_session_difficulty = truediff >= current_difficulty as u128;

    match stratum_context.mode {
        // P2Poolv2: emit to the share chain only when the share meets the
        // ASERT pool target carried in the commitment. Hashrate and vardiff
        // accounting below still run on every share, so a miner whose
        // session difficulty is below the pool target is measured accurately.
        PoolMode::P2poolv2 => {
            if let Some(commitment) = &job.share_commitment {
                let pool_target = bitcoin::Target::from_compact(commitment.bits);
                if pool_target.is_met_by(block_hash) {
                    // The full coinbase exists only here, so the proof is
                    // built now. Every coinbase this pool builds ends with the
                    // commitment, so a failure is a malformed job, not the
                    // miner's fault: log it and keep the share off the share
                    // chain. Hashrate and vardiff accounting still run below.
                    match CoinbaseProof::from_coinbase(
                        &validation_result.coinbase,
                        commitment.share_witness_root,
                    ) {
                        Ok(coinbase_proof) => {
                            stratum_context
                                .emissions_tx
                                .send(Emission {
                                    header: validation_result.header,
                                    blocktemplate: job.blocktemplate.clone(),
                                    share_commitment: commitment.clone(),
                                    template_merkle_branches: job.template_merkle_branches.clone(),
                                    bitcoin_coinbase: validation_result.coinbase.clone(),
                                    coinbase_proof,
                                })
                                .await
                                .map_err(|e| {
                                    Error::SubmitFailure(format!(
                                        "Failed to send share to store: {e}"
                                    ))
                                })?;
                        }
                        Err(error) => {
                            error!(
                                "Failed to build coinbase proof for job {job_id}, not emitting to share chain: {error}"
                            );
                        }
                    }
                } else {
                    debug!(
                        "Share does not meet pool difficulty, not emitting to share chain: hash {} target {:?}",
                        block_hash, commitment.bits
                    );
                }
            }
        }
        // Hydrapool: no pool target and no share chain. Queue the share for
        // the PPLNS share worker only when its hash meets the session
        // difficulty it will be credited at; the send only enqueues, so the
        // connection returns to the miner without waiting on the store.
        PoolMode::Hydrapool => {
            if hash_meets_session_difficulty {
                stratum_context
                    .pplns_shares_tx
                    .send(stratum_share.clone())
                    .await
                    .map_err(|e| {
                        Error::SubmitFailure(format!("Failed to send PPLNS share to store: {e}"))
                    })?;
            }
        }
    }

    session.last_share_time = Some(SystemTime::now());

    // If we are in testing mode and ignoring difficulty, accept share as meeting current difficulty
    let meets_session_difficulty =
        stratum_context.ignore_difficulty || hash_meets_session_difficulty;

    if meets_session_difficulty {
        let _ = stratum_context
            .metrics
            .record_share_accepted(stratum_share, truediff as u64)
            .await;
    } else {
        let _ = stratum_context.metrics.record_share_rejected().await;
    }

    let (new_difficulty, _is_first_share) = session.difficulty_adjuster.record_share_submission(
        truediff,
        job_id,
        session.suggested_difficulty,
        SystemTime::now(),
    );

    let mut response = vec![Message::Response(Response::new_ok(
        message.id,
        json!(meets_session_difficulty),
    ))];
    match new_difficulty {
        Some(difficulty) => {
            response.push(Message::SetDifficulty(SetDifficultyNotification::new(
                difficulty,
            )));
            Ok(response)
        }
        None => Ok(response),
    }
}

/// Submit block to bitcoind using the shared RPC client.
pub async fn submit_block(block: &Block, bitcoindrpc_client: &BitcoindRpcClient) {
    tracing::info!(
        "Submitting block to bitcoind: {:?}",
        block.header.block_hash()
    );
    match bitcoindrpc_client.submit_block(block).await {
        Ok(_) => info!("Block submitted successfully"),
        Err(e) => error!("Failed to submit block: {}", e),
    }
}

/// Build full block from header, coinbase and blocktemplate
/// Only called for the rare case of finding a bitcoin block (real auto-submit
/// in non-sim builds; the sim statistical block-find under `sim`).
pub(crate) fn build_full_block(
    header: Header,
    coinbase: bitcoin::Transaction,
    blocktemplate: &BlockTemplate,
) -> Block {
    let mut all_transactions = Vec::with_capacity(blocktemplate.transactions.len() + 1);
    all_transactions.push(coinbase);
    all_transactions.extend(blocktemplate.decode_transactions());

    Block {
        header,
        txdata: all_transactions,
    }
}

/// Use bitcoin mainnet max attainable target to convert the hash into difficulty
/// This global difficulty to used to track difficult adjustment by the pool, independent of the chain that is being mined.
fn get_true_difficulty(hash: &bitcoin::BlockHash) -> u128 {
    let mut bytes = hash.to_byte_array();
    bytes.reverse();
    let diff = u128::from_str_radix(&hex::encode(&bytes[..16]), 16).unwrap();
    (0xFFFF_u128 << (208 - 128)) / diff
}

#[cfg(test)]
mod handle_submit_tests {
    use super::*;
    use crate::accounting::stats::metrics;
    use crate::shares::share_commitment::ShareCommitment;
    use crate::stratum::difficulty_adjuster::{DifficultyAdjuster, MockDifficultyAdjusterTrait};
    use crate::stratum::messages::Id;
    use crate::stratum::messages::SetDifficultyNotification;
    use crate::stratum::session::Session;
    use crate::stratum::work::gbt::build_merkle_branches_for_template;
    use crate::stratum::work::tracker::start_tracker_actor;
    use crate::test_utils::{
        TEST_COINBASE_NSECS, build_pool_job_submit, create_test_commitment,
        load_valid_stratum_work_components, setup_test_chain_store_handle,
    };
    use bitcoin::BlockHash;
    use bitcoindrpc::test_utils::{mock_submit_block_with_any_body, setup_mock_bitcoin_rpc};
    use p2poolv2_config::DEFAULT_VERSION_MASK;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    #[test]
    fn test_true_difficulty() {
        let hash = "000000000007f7453abd3f11338c165bf4876c086979630ed6f35ddbe59125a9"
            .parse::<BlockHash>()
            .unwrap();
        let difficulty = get_true_difficulty(&hash);
        assert_eq!(difficulty, 8226);
    }

    #[tokio::test]
    async fn test_handle_submit_meets_difficulty_should_submit() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let (template, notify, submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let merkle_branches = build_merkle_branches_for_template(&template)
            .into_iter()
            .map(bitcoin::TxMerkleNode::from_raw_hash)
            .collect();
        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            Some(create_test_commitment()),
            TEST_COINBASE_NSECS,
            merkle_branches,
            job_id,
        );

        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, mut pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let message = handle_submit(submit, &mut session, ctx).await.unwrap();

        let response = match &message[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        assert_eq!(response.id, Some(Id::Number(4)));

        // The response should indicate that the share met required difficulty
        assert_eq!(response.result, Some(json!(true)));

        // P2Poolv2 mode never queues a hydrapool PPLNS share
        assert!(pplns_shares_rx.try_recv().is_err());

        // Verify that the block is submitted to the mock server
        mock_server.verify().await;

        assert_eq!(metrics_handle.get_metrics().await.accepted_total, 1);
    }

    #[tokio::test]
    async fn test_handle_submit_a_meets_difficulty_should_submit() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let (template, notify, submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/a/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            Some(create_test_commitment()),
            TEST_COINBASE_NSECS,
            vec![],
            job_id,
        );

        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let response = handle_submit(submit, &mut session, ctx).await.unwrap();

        let response = match &response[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        assert_eq!(response.id, Some(Id::Number(4)));

        // The response should indicate that the share met required difficulty
        assert_eq!(response.result, Some(json!(true)));

        // Verify that the block is submitted to the mock server
        mock_server.verify().await;

        assert_eq!(metrics_handle.get_metrics().await.accepted_total, 1);
    }

    #[tokio::test]
    async fn test_handle_submit_with_version_rolling_meets_difficulty_should_submit() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let (template, notify, submit, authorize_response) = load_valid_stratum_work_components(
            "../p2poolv2_tests/test_data/validation/stratum/with_version_rolling/",
        );

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            Some(create_test_commitment()),
            TEST_COINBASE_NSECS,
            vec![],
            job_id,
        );

        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let response = handle_submit(submit, &mut session, ctx).await.unwrap();

        let response = match &response[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        assert_eq!(response.id, Some(Id::Number(5)));

        // The response should indicate that the share met required difficulty
        assert_eq!(response.result, Some(json!(true)));

        // Verify that the block is submitted to the mock server
        mock_server.verify().await;

        assert_eq!(metrics_handle.get_metrics().await.accepted_total, 1);
    }

    #[tokio::test]
    async fn test_handle_submit_triggers_difficulty_adjustment() {
        let ctx = MockDifficultyAdjusterTrait::new_context();
        ctx.expect().returning(|_, _, _| {
            let mut mock = MockDifficultyAdjusterTrait::default();
            mock.expect_record_share_submission().returning(
                |_difficulty, _job_id, _suggested_difficulty, _current_timestamp| {
                    (Some(12345), false)
                },
            );
            mock.expect_get_current_difficulty().returning(|| 1u64);
            mock
        });

        let mut session =
            Session::<MockDifficultyAdjusterTrait>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let (template, notify, submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/a/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            Some(create_test_commitment()),
            TEST_COINBASE_NSECS,
            vec![],
            job_id,
        );

        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let message = handle_submit(submit, &mut session, ctx).await.unwrap();

        match &message[..] {
            [
                Message::Response(Response {
                    id: _,
                    result,
                    error: _,
                }),
                Message::SetDifficulty(SetDifficultyNotification { method: _, params }),
            ] => {
                assert_eq!(result, &Some(json!(true)));
                assert_eq!(params[0], 12345);
            }
            _ => panic!("Expected SetDifficultyNotification message"),
        }

        mock_server.verify().await;
    }

    #[tokio::test]
    async fn test_handle_submit_with_stale_job_returns_error() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (_mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        let (_template, _notify, submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/a/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 10000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let message = handle_submit(submit, &mut session, ctx).await.unwrap();

        let response = match &message[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        // Should return stale error
        assert_eq!(response.result, None);
        let err = response.error.as_ref().unwrap();
        assert_eq!(err.code, 21, "should be JobNotFound (code 21)");
        assert_eq!(err.message, "Job not found");
    }

    /// Session difficulty decides the miner response and metrics; the pool
    /// target alone decides share chain emission. A share below session
    /// difficulty that meets the pool target is rejected to the miner but
    /// still emitted.
    #[tokio::test]
    async fn test_handle_submit_with_less_difficulty_than_session_is_rejected_but_emitted() {
        let mut session =
            Session::<DifficultyAdjuster>::new(10_000, 10_000, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        session.enonce1 = u32::from_le_bytes([0xde, 0xad, 0xbe, 0xef]);
        session.enonce1_hex = "deadbeef".to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let submit = build_pool_job_submit(&tracker_handle, &session.enonce1_hex);

        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 10_000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let message = handle_submit(submit, &mut session, ctx).await.unwrap();

        let response = match &message[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        assert_eq!(response.id, Some(Id::Number(4)));
        assert_eq!(response.result, Some(json!(false)));

        let share = emissions_rx.try_recv().unwrap();
        assert_eq!(
            share.share_commitment.miner_bitcoin_address,
            create_test_commitment().miner_bitcoin_address
        );

        assert_eq!(metrics_handle.get_metrics().await.accepted_total, 0);
        assert_eq!(metrics_handle.get_metrics().await.rejected_total, 1);
    }

    #[tokio::test]
    async fn test_handle_submit_duplicate_share_is_rejected() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        session.enonce1 = u32::from_le_bytes([0xde, 0xad, 0xbe, 0xef]);
        session.enonce1_hex = "deadbeef".to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let submit = build_pool_job_submit(&tracker_handle, &session.enonce1_hex);

        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        // First submission is emitted
        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx: emissions_tx.clone(),
            pplns_shares_tx: pplns_shares_tx.clone(),
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle: chain_store_handle.clone(),
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let message = handle_submit(submit.clone(), &mut session, ctx)
            .await
            .unwrap();

        let response = match &message[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };
        assert!(response.error.is_none());
        let _share = emissions_rx.try_recv().unwrap();

        // Second submission of the same share should be rejected as duplicate
        let ctx2 = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let message2 = handle_submit(submit, &mut session, ctx2).await.unwrap();

        let response2 = match &message2[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        // Duplicate submission should return error code 22
        assert_eq!(response2.result, None);
        let err = response2.error.as_ref().unwrap();
        assert_eq!(err.code, 22, "should be DuplicateShare (code 22)");
        assert_eq!(err.message, "Duplicate share");

        // No additional emission should be sent for duplicate
        assert!(emissions_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_handle_submit_accepts_low_difficulty_share_when_ignore_difficulty_is_true() {
        // Session difficulty 10_000 is far above what the share's hash meets
        let mut session =
            Session::<DifficultyAdjuster>::new(10_000, 10_000, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        session.enonce1 = u32::from_le_bytes([0xde, 0xad, 0xbe, 0xef]);
        session.enonce1_hex = "deadbeef".to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let submit = build_pool_job_submit(&tracker_handle, &session.enonce1_hex);

        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 10_000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let message = handle_submit(submit, &mut session, ctx).await.unwrap();

        let response = match &message[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        assert_eq!(response.id, Some(Id::Number(4)));

        // The response should indicate the share is accepted even though it doesn't meet session difficulty
        assert_eq!(response.result, Some(json!(true)));

        // Emission should be sent
        let share = emissions_rx.try_recv().unwrap();
        assert_eq!(
            share.share_commitment.miner_bitcoin_address,
            create_test_commitment().miner_bitcoin_address
        );

        // Share should be counted as accepted (not rejected)
        // accepted_difficulty_total tracks the session difficulty of accepted shares (10000)
        assert_eq!(metrics_handle.get_metrics().await.accepted_total, 1);
        assert_eq!(
            metrics_handle.get_metrics().await.accepted_difficulty_total,
            10000
        );
        assert_eq!(metrics_handle.get_metrics().await.rejected_total, 0);
    }

    /// The emitted coinbase proof is the midstate of the coinbase the miner
    /// hashed, and the template merkle branches are passed through from the
    /// job.
    #[tokio::test]
    async fn test_handle_submit_emits_coinbase_proof_of_share_coinbase() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        session.enonce1 = u32::from_le_bytes([0xde, 0xad, 0xbe, 0xef]);
        session.enonce1_hex = "deadbeef".to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let submit = build_pool_job_submit(&tracker_handle, &session.enonce1_hex);

        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        handle_submit(submit, &mut session, ctx).await.unwrap();

        let share = emissions_rx.try_recv().unwrap();
        let expected_proof = CoinbaseProof::from_coinbase(
            &share.bitcoin_coinbase,
            share.share_commitment.share_witness_root,
        )
        .unwrap();
        assert_eq!(share.coinbase_proof, expected_proof);

        let job = tracker_handle
            .get_job(tracker_handle.get_latest_job_id())
            .unwrap();
        assert_eq!(share.template_merkle_branches, job.template_merkle_branches);
    }

    #[tokio::test]
    async fn test_handle_submit_not_subscribed_returns_error() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        // session.subscribed is false by default
        let submit = SimpleRequest::new_submit(
            1,
            "worker".to_string(),
            "1".to_string(),
            "00000000".to_string(),
            "504e86ed".to_string(),
            "e9695791".to_string(),
        );
        let tracker_handle = start_tracker_actor();
        let (emissions_tx, _) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let (chain_store_handle, _) = setup_test_chain_store_handle(true).await;
        let (_mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Regtest,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(r)] => r,
            _ => panic!("expected Response"),
        };
        assert_eq!(response.result, None);
        let err = response.error.as_ref().unwrap();
        assert_eq!(err.code, 25, "should be NotSubscribed (code 25)");
        assert_eq!(err.message, "Not subscribed");
    }

    #[tokio::test]
    async fn test_handle_submit_unknown_job_id_returns_invalid_jobid() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (_mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        let (template, _notify, _submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/a/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        // Insert a job to set latest_job_id, then submit an ID beyond it
        let inserted_id = tracker_handle.insert_job(
            Arc::new(template),
            "cb1".to_string(),
            "cb2".to_string(),
            Some(create_test_commitment()),
            TEST_COINBASE_NSECS,
            vec![],
            tracker_handle.get_next_job_id(),
        );
        let unknown_job_id = tracker_handle.get_latest_job_id().0 + 1;

        let submit = SimpleRequest::new_submit(
            1,
            "worker".to_string(),
            format!("{unknown_job_id:x}"),
            "00000000".to_string(),
            "504e86ed".to_string(),
            "e9695791".to_string(),
        );

        let (emissions_tx, _) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        // Verify the inserted job is properly registered
        let _ = inserted_id;

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(r)] => r,
            _ => panic!("expected Response"),
        };
        assert_eq!(response.result, None);
        let err = response.error.as_ref().unwrap();
        assert_eq!(err.code, 21, "should be JobNotFound (code 21)");
        assert_eq!(err.message, "Job not found");
    }

    #[tokio::test]
    async fn test_handle_submit_validation_failure_returns_other_unknown_with_message() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        session.enonce1_hex = "deadbeef".to_string();
        session.user_id = Some(1);

        let tracker_handle = start_tracker_actor();

        let template: BlockTemplate = serde_json::from_value(json!({
             "version": 536870912,
            "rules": [],
            "vbavailable": {},
            "vbrequired": 0,
            "previousblockhash": "0000000000000000000000000000000000000000000000000000000000000000",
            "transactions": [],
            "coinbaseaux": {},
            "coinbasevalue": 5000000000_u64,
            "longpollid": "0",
            "target": "00000000ffff0000000000000000000000000000000000000000000000000000",
            "mintime": 1,
            "mutable": [],
            "noncerange": "00000000ffffffff",
            "sigoplimit": 80000,
            "sizelimit": 4000000,
            "weightlimit": 4000000,
            "curtime": 1,
            "bits": "1d00ffff",
            "height": 1,
            "default_witness_commitment": ""
        }))
        .unwrap();

        // bad coinbase fields make sure the validation fails
        let job_id = JobId(1);
        let _ = tracker_handle.insert_job(
            Arc::new(template),
            "deadbeef".to_string(),
            "cafebabe".to_string(),
            None,
            0,
            vec![],
            job_id,
        );

        let submit = SimpleRequest::new_submit(
            4,
            "worker".to_string(),
            "1".to_string(),
            "00000000".to_string(),
            "504e86ed".to_string(),
            "e9695791".to_string(),
        );

        let (_mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let (emissions_tx, _) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Regtest,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(r)] => r,
            _ => panic!("expected Response"),
        };
        assert_eq!(response.result, None);
        let err = response.error.as_ref().unwrap();
        assert_eq!(err.code, 20, "should be OtherUnknown (code 20)");
        assert!(
            err.message.starts_with("Invalid parameters provided:"),
            "error message should contain the validation failure reason, got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn test_handle_submit_bad_nonce_returns_error_not_panic() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (template, notify, _submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());
        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            None,
            TEST_COINBASE_NSECS,
            vec![],
            job_id,
        );

        let submit = SimpleRequest::new_submit(
            4,
            "worker".to_string(),
            notify.params.job_id.clone(),
            "0000000000000000".to_string(),
            "504e86ed".to_string(),
            "ZZZZZZZZ".to_string(),
        );

        let (_mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let (emissions_tx, _) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Regtest,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(r)] => r,
            _ => panic!("expected Response"),
        };
        assert_eq!(response.result, None);
        let err = response.error.as_ref().unwrap();
        assert_eq!(err.code, 20, "should be OtherUnknown (code 20)");
        assert_eq!(err.message, "Invalid parameters provided: Bad nonce");
    }

    #[tokio::test]
    async fn test_handle_submit_none_version_bits_returns_error_not_panic() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (template, notify, _submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());
        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            None,
            TEST_COINBASE_NSECS,
            vec![],
            job_id,
        );

        // Build a submit with 6 params where the 6th (version bits) is None
        let submit = SimpleRequest {
            id: Some(Id::Number(4)),
            method: std::borrow::Cow::Owned("mining.submit".to_string()),
            params: std::borrow::Cow::Owned(vec![
                Some("worker".to_string()),
                Some(notify.params.job_id.clone()),
                Some("0000000000000000".to_string()),
                Some("504e86ed".to_string()),
                Some("e9695791".to_string()),
                None, // version bits is None
            ]),
        };

        let (_mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let (emissions_tx, _) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Regtest,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(r)] => r,
            _ => panic!("expected Response"),
        };
        assert_eq!(response.result, None);
        let err = response.error.as_ref().unwrap();
        assert_eq!(err.code, 20, "should be OtherUnknown (code 20)");
        assert_eq!(
            err.message,
            "Invalid parameters provided: Missing version bits"
        );
    }

    #[tokio::test]
    async fn test_handle_submit_unauthorized_returns_error() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        // user_id is None -- simulates a session where authorize partially
        // failed (username set but register_user errored)
        assert!(session.user_id.is_none());

        let submit = SimpleRequest::new_submit(
            1,
            "worker".to_string(),
            "1".to_string(),
            "00000000".to_string(),
            "504e86ed".to_string(),
            "e9695791".to_string(),
        );
        let tracker_handle = start_tracker_actor();
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let (_mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Regtest,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(r)] => r,
            _ => panic!("expected Response"),
        };
        assert_eq!(response.result, None);
        let err = response.error.as_ref().unwrap();
        assert_eq!(err.code, 24, "should be UnauthorizedWorker (code 24)");
        assert_eq!(err.message, "Not authorized");
    }

    /// Build a commitment with an impossibly hard pool target so that
    /// any test share will fail the ASERT pool difficulty check.
    fn create_hard_pool_difficulty_commitment() -> ShareCommitment {
        let mut commitment = create_test_commitment();
        // 0x01003456 is an extremely hard target that no test share can meet
        commitment.bits = bitcoin::CompactTarget::from_consensus(0x01003456);
        commitment
    }

    /// A share that meets the miner's session difficulty but not the pool
    /// difficulty target must still be accepted (the miner met its assigned
    /// difficulty) and counted toward hashrate metrics, but must NOT be emitted
    /// to the share chain. This keeps hashrate reporting accurate for miners
    /// whose session difficulty is below the pool target.
    #[tokio::test]
    async fn test_p2poolv2_mode_accepts_and_accounts_share_below_pool_difficulty_without_emitting()
    {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let (template, notify, submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let merkle_branches = build_merkle_branches_for_template(&template)
            .into_iter()
            .map(bitcoin::TxMerkleNode::from_raw_hash)
            .collect();
        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            Some(create_hard_pool_difficulty_commitment()),
            TEST_COINBASE_NSECS,
            merkle_branches,
            job_id,
        );

        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, _pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(r)] => r,
            _ => panic!("expected Response"),
        };
        // Share met the miner's session difficulty, so it is accepted.
        assert_eq!(response.result, Some(json!(true)));

        // Share must NOT be emitted to the share chain: it does not meet the
        // pool difficulty target.
        assert!(
            emissions_rx.try_recv().is_err(),
            "share below pool difficulty must not be emitted to the share chain"
        );

        // Share must still be counted toward hashrate metrics.
        assert_eq!(metrics_handle.get_metrics().await.accepted_total, 1);
    }

    #[tokio::test]
    async fn test_hydrapool_mode_accepts_share_despite_hard_pool_difficulty() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let (template, notify, submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let merkle_branches = build_merkle_branches_for_template(&template)
            .into_iter()
            .map(bitcoin::TxMerkleNode::from_raw_hash)
            .collect();
        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            Some(create_hard_pool_difficulty_commitment()),
            TEST_COINBASE_NSECS,
            merkle_branches,
            job_id,
        );

        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, mut pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::Hydrapool,
            miner_address: None,
        };

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(response)] => response,
            _ => panic!("expected Response"),
        };
        // Share is accepted despite not meeting pool difficulty
        assert_eq!(response.result, Some(json!(true)));

        // Share is queued for the PPLNS share worker at the session
        // difficulty, and never emitted to the share chain.
        let share = pplns_shares_rx.try_recv().unwrap();
        assert_eq!(
            share.btcaddress,
            Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string())
        );
        assert_eq!(share.difficulty, 1);
        assert!(
            emissions_rx.try_recv().is_err(),
            "hydrapool share must not be emitted to the share chain"
        );
    }

    /// Regression for GHSA-mmw7-mxvq-79wq: a hydrapool share whose hash does
    /// not meet the session difficulty must not be stored for PPLNS, because
    /// it would be credited at the session difficulty the miner chose.
    #[tokio::test]
    async fn test_hydrapool_mode_does_not_store_share_below_session_difficulty() {
        let mut session =
            Session::<DifficultyAdjuster>::new(10_000, 10_000, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let (template, notify, submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            None,
            TEST_COINBASE_NSECS,
            vec![],
            job_id,
        );

        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, mut pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 10_000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::Hydrapool,
            miner_address: None,
        };

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(response)] => response,
            _ => panic!("expected Response"),
        };
        assert_eq!(response.result, Some(json!(false)));

        assert!(
            pplns_shares_rx.try_recv().is_err(),
            "hydrapool share below session difficulty must not be stored"
        );
        assert!(
            emissions_rx.try_recv().is_err(),
            "hydrapool share below session difficulty must not be emitted"
        );
        assert_eq!(metrics_handle.get_metrics().await.rejected_total, 1);
    }

    /// `ignore_difficulty` only changes the miner response and metrics. It
    /// must not let a hydrapool share below session difficulty into PPLNS
    /// storage.
    #[tokio::test]
    async fn test_hydrapool_mode_ignore_difficulty_does_not_store_share_below_session_difficulty() {
        let mut session =
            Session::<DifficultyAdjuster>::new(10_000, 10_000, None, DEFAULT_VERSION_MASK);
        session.subscribed = true;
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let (template, notify, submit, authorize_response) =
            load_valid_stratum_work_components("../p2poolv2_tests/test_data/validation/stratum/b/");

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();
        session.btcaddress = Some("tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d".to_string());
        session.user_id = Some(1);

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let _ = tracker_handle.insert_job(
            Arc::new(template),
            notify.params.coinbase1.to_string(),
            notify.params.coinbase2.to_string(),
            None,
            TEST_COINBASE_NSECS,
            vec![],
            job_id,
        );

        let (emissions_tx, mut emissions_rx) = mpsc::channel(10);
        let (pplns_shares_tx, mut pplns_shares_rx) = mpsc::channel(10);
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle: tracker_handle.clone(),
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 10_000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            pplns_shares_tx,
            network: bitcoin::network::Network::Signet,
            metrics: metrics_handle.clone(),
            chain_store_handle,
            mode: PoolMode::Hydrapool,
            miner_address: None,
        };

        let messages = handle_submit(submit, &mut session, ctx).await.unwrap();
        let response = match &messages[..] {
            [Message::Response(response)] => response,
            _ => panic!("expected Response"),
        };
        assert_eq!(response.result, Some(json!(true)));

        assert!(
            pplns_shares_rx.try_recv().is_err(),
            "hydrapool share below session difficulty must not be stored"
        );
        assert!(
            emissions_rx.try_recv().is_err(),
            "hydrapool share below session difficulty must not be emitted"
        );
        assert_eq!(metrics_handle.get_metrics().await.accepted_total, 1);
    }
}
