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

use crate::difficulty_adjuster::DifficultyAdjusterTrait;
use crate::error::Error;
use crate::messages::{Message, Response, SetDifficultyNotification, SimpleRequest};
use crate::session::Session;
use crate::work::difficulty::validate::validate_submission_difficulty;
use crate::work::tracker::{JobId, TrackerHandle};
use bitcoin::blockdata::block::Block;
use bitcoin::hashes::Hash;
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient};
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
pub async fn handle_submit<'a, D: DifficultyAdjusterTrait>(
    message: SimpleRequest<'a>,
    session: &mut Session<D>,
    tracker_handle: TrackerHandle,
    bitcoinrpc_config: BitcoinRpcConfig,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.submit message");
    if message.params.len() < 4 {
        return Err(Error::InvalidParams("Missing parameters".into()));
    }

    let id = message.params[1].as_ref().unwrap();

    let job_id =
        u64::from_str_radix(id, 16).map_err(|_| Error::InvalidParams("Invalid job_id".into()))?;

    let job = match tracker_handle.get_job(JobId(job_id)).await {
        Ok(Some(job)) => job,
        _ => {
            debug!("Job not found for job_id: {}", job_id);
            return Ok(vec![Message::Response(Response::new_ok(
                message.id,
                json!(false),
            ))]);
        }
    };

    // Validate the difficulty of the submitted share
    let block = match validate_submission_difficulty(
        &job,
        &message,
        &session.enonce1_hex,
        session.version_mask,
    ) {
        Ok(block) => block,
        Err(e) => {
            info!("Share validation failed: {}", e);
            return Ok(vec![Message::Response(Response::new_ok(
                message.id,
                json!(false),
            ))]);
        }
    };

    // Submit block asap, do difficulty adjustment after submission
    submit_block(&block, bitcoinrpc_config).await;

    // Mining difficulties are tracked as `truediffone`, i.e. difficulty is computed relative to mainnet
    let truediff = get_true_difficulty(&block.block_hash());
    debug!("True difficulty: {}", truediff);

    let (new_difficulty, _is_first_share) = session.difficulty_adjuster.record_share_submission(
        truediff,
        job_id,
        session.suggested_difficulty,
        SystemTime::now(),
    );

    if let Some(difficulty) = new_difficulty {
        return Ok(vec![Message::SetDifficulty(
            SetDifficultyNotification::new(difficulty),
        )]);
    }

    Ok(vec![Message::Response(Response::new_ok(
        message.id,
        json!(true),
    ))])
}

/// Submit block to bitcoind
///
/// Build bitcoindrpc from config and call submit block
pub async fn submit_block(block: &Block, bitcoinrpc_config: BitcoinRpcConfig) {
    info!(
        "Submitting block to bitcoind: {:?}",
        block.header.block_hash()
    );
    let rpc = BitcoindRpcClient::new(
        &bitcoinrpc_config.url,
        &bitcoinrpc_config.username,
        &bitcoinrpc_config.password,
    );
    match rpc {
        Ok(bitcoind) => match bitcoind.submit_block(block).await {
            Ok(_) => info!("Block submitted successfully"),
            Err(e) => error!("Failed to submit block: {}", e),
        },
        Err(e) => {
            error!("Failed to create Bitcoind RPC client: {}", e);
        }
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
    use crate::difficulty_adjuster::{DifficultyAdjuster, MockDifficultyAdjusterTrait};
    use crate::messages::SetDifficultyNotification;
    use crate::messages::{Id, Notify, SimpleRequest};
    use crate::session::Session;
    use crate::work::gbt::BlockTemplate;
    use crate::work::tracker::start_tracker_actor;
    use bitcoin::BlockHash;
    use bitcoindrpc::test_utils::{mock_submit_block_with_any_body, setup_mock_bitcoin_rpc};
    use std::sync::Arc;

    #[test_log::test]
    fn test_true_difficulty() {
        let hash = "000000000007f7453abd3f11338c165bf4876c086979630ed6f35ddbe59125a9"
            .parse::<BlockHash>()
            .unwrap();
        let difficulty = get_true_difficulty(&hash);
        assert_eq!(difficulty, 8226);
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_submit_meets_difficulty_should_submit() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
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
        let submit: SimpleRequest = serde_json::from_str(&submit_str).unwrap();

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

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let _ = tracker_handle
            .insert_job(
                Arc::new(template),
                notify.params.coinbase1.to_string(),
                notify.params.coinbase2.to_string(),
                job_id,
            )
            .await;

        let message = handle_submit(submit, &mut session, tracker_handle, bitcoinrpc_config)
            .await
            .unwrap();

        let response = match &message[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        assert_eq!(response.id, Some(Id::Number(4)));

        // The response should indicate that the share met required difficulty
        assert_eq!(response.result, Some(json!(true)));

        // Verify that the block was not submitted to the mock server
        mock_server.verify().await;
    }

    #[tokio::test]
    async fn test_handle_submit_a_meets_difficulty_should_submit() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let template_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/template.json"),
        )
        .unwrap();
        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();

        let notify_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/notify.json"),
        )
        .unwrap();
        let notify: Notify = serde_json::from_str(&notify_str).unwrap();

        let submit_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/submit.json"),
        )
        .unwrap();
        let submit: SimpleRequest = serde_json::from_str(&submit_str).unwrap();

        let authorize_response_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/authorize_response.json"),
        )
        .unwrap();
        let authorize_response: Response = serde_json::from_str(&authorize_response_str).unwrap();

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let _ = tracker_handle
            .insert_job(
                Arc::new(template),
                notify.params.coinbase1.to_string(),
                notify.params.coinbase2.to_string(),
                job_id,
            )
            .await;

        let response = handle_submit(submit, &mut session, tracker_handle, bitcoinrpc_config)
            .await
            .unwrap();

        let response = match &response[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        assert_eq!(response.id, Some(Id::Number(4)));

        // The response should indicate that the share met required difficulty
        assert_eq!(response.result, Some(json!(true)));

        // Verify that the block was not submitted to the mock server
        mock_server.verify().await;
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_submit_with_version_rolling_meets_difficulty_should_submit() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        let template_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/with_version_rolling/template.json"),
        )
        .unwrap();
        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();

        let notify_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/with_version_rolling/notify.json"),
        )
        .unwrap();
        let notify: Notify = serde_json::from_str(&notify_str).unwrap();

        let submit_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/with_version_rolling/submit.json"),
        )
        .unwrap();
        let submit: SimpleRequest = serde_json::from_str(&submit_str).unwrap();

        let authorize_response_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/with_version_rolling/authorize_response.json"),
        )
        .unwrap();
        let authorize_response: Response = serde_json::from_str(&authorize_response_str).unwrap();

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let _ = tracker_handle
            .insert_job(
                Arc::new(template),
                notify.params.coinbase1.to_string(),
                notify.params.coinbase2.to_string(),
                job_id,
            )
            .await;

        let response = handle_submit(submit, &mut session, tracker_handle, bitcoinrpc_config)
            .await
            .unwrap();

        let response = match &response[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        assert_eq!(response.id, Some(Id::Number(5)));

        // The response should indicate that the share met required difficulty
        assert_eq!(response.result, Some(json!(true)));

        // Verify that the block was not submitted to the mock server
        mock_server.verify().await;
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
            mock
        });

        let mut session = Session::<MockDifficultyAdjusterTrait>::new(1, 1, None, 0x1fffe000);
        let tracker_handle = start_tracker_actor();

        let (mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        mock_submit_block_with_any_body(&mock_server).await;

        // Use test data from "a" as a base
        let template_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/template.json"),
        )
        .unwrap();
        let template: BlockTemplate = serde_json::from_str(&template_str).unwrap();

        let notify_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/notify.json"),
        )
        .unwrap();
        let notify: Notify = serde_json::from_str(&notify_str).unwrap();

        let submit_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/submit.json"),
        )
        .unwrap();
        let submit: SimpleRequest = serde_json::from_str(&submit_str).unwrap();

        let authorize_response_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/authorize_response.json"),
        )
        .unwrap();
        let authorize_response: Response = serde_json::from_str(&authorize_response_str).unwrap();

        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();

        let job_id = JobId(u64::from_str_radix(&notify.params.job_id, 16).unwrap());

        let _ = tracker_handle
            .insert_job(
                Arc::new(template),
                notify.params.coinbase1.to_string(),
                notify.params.coinbase2.to_string(),
                job_id,
            )
            .await;

        let message = handle_submit(submit, &mut session, tracker_handle, bitcoinrpc_config)
            .await
            .unwrap();

        match &message[..] {
            [Message::SetDifficulty(SetDifficultyNotification { method: _, params })] => {
                assert_eq!(params[0], 12345);
            }
            _ => panic!("Expected SetDifficultyNotification message"),
        }

        mock_server.verify().await;
    }

    #[tokio::test]
    async fn test_handle_submit_with_unknown_job_id_returns_false() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let tracker_handle = start_tracker_actor();

        let (_mock_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;

        // Prepare a valid submit message but with a job_id that is not inserted into the tracker
        let submit_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/submit.json"),
        )
        .unwrap();
        let mut submit: SimpleRequest = serde_json::from_str(&submit_str).unwrap();

        // Overwrite job_id param to an unknown value (e.g., "deadbeef")
        if submit.params.len() > 1 {
            submit.params.to_mut()[1] = Some("deadbeef".to_string());
        }

        // Set enonce1 from authorize_response
        let authorize_response_str = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../tests/test_data/validation/stratum/a/authorize_response.json"),
        )
        .unwrap();
        let authorize_response: Response = serde_json::from_str(&authorize_response_str).unwrap();
        let enonce1 = authorize_response.result.unwrap()[1].clone();
        let enonce1: &str = enonce1.as_str().unwrap();
        session.enonce1 =
            u32::from_le_bytes(hex::decode(enonce1).unwrap().as_slice().try_into().unwrap());
        session.enonce1_hex = enonce1.to_string();

        let message = handle_submit(submit, &mut session, tracker_handle, bitcoinrpc_config)
            .await
            .unwrap();

        let response = match &message[..] {
            [Message::Response(response)] => response,
            _ => panic!("Expected a Response message"),
        };

        // Should return result false for unknown job_id
        assert_eq!(response.result, Some(json!(false)));
    }
}
