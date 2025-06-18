// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

use crate::error::Error;
use crate::messages::{Request, Response};
use crate::session::Session;
use crate::work::difficulty::validate::validate_submission_difficulty;
use crate::work::tracker::{JobId, TrackerHandle};
use bitcoin::blockdata::block::Block;
use bitcoindrpc::{BitcoinRpcConfig, BitcoindRpcClient};
use serde_json::json;
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
pub async fn handle_submit<'a>(
    message: Request<'a>,
    session: &mut Session,
    tracker_handle: TrackerHandle,
    bitcoinrpc_config: BitcoinRpcConfig,
) -> Result<Response<'a>, Error> {
    debug!("Handling mining.submit message");
    if message.params.len() < 4 {
        return Err(Error::InvalidParams);
    }

    let job_id = u64::from_str_radix(&message.params[1], 16).map_err(|_| Error::InvalidParams)?;

    let job = match tracker_handle.get_job(JobId(job_id)).await {
        Ok(Some(job)) => job,
        _ => {
            return Err(Error::SubmitFailure(
                "No job found for the given ID".to_string(),
            ))
        }
    };

    // Validate the difficulty of the submitted share
    let block = match validate_submission_difficulty(&job, &message, &session.enonce1_hex) {
        Ok(block) => block,
        Err(e) => {
            info!("Share validation failed: {}", e);
            return Ok(Response::new_ok(message.id, json!(false)));
        }
    };

    submit_block(block, bitcoinrpc_config).await;
    Ok(Response::new_ok(message.id, json!(true)))
}

/// Submit block to bitcoind
///
/// Build bitcoindrpc from config and call submit block
pub async fn submit_block(block: Block, bitcoinrpc_config: BitcoinRpcConfig) {
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
        Ok(bitcoind) => match bitcoind.submit_block(&block).await {
            Ok(_) => info!("Block submitted successfully"),
            Err(e) => error!("Failed to submit block: {}", e),
        },
        Err(e) => {
            error!("Failed to create Bitcoind RPC client: {}", e);
        }
    }
}

#[cfg(test)]
mod handle_submit_tests {
    use super::*;
    use crate::messages::{Id, Notify, Request};
    use crate::session::Session;
    use crate::work::gbt::BlockTemplate;
    use crate::work::tracker::start_tracker_actor;
    use bitcoindrpc::test_utils::{mock_submit_block_with_any_body, setup_mock_bitcoin_rpc};
    use std::sync::Arc;

    #[test_log::test(tokio::test)]
    async fn test_handle_submit_meets_difficulty_should_submit() {
        let mut session = Session::new(1, None, 2);
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
        let submit: Request = serde_json::from_str(&submit_str).unwrap();

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

        let response = handle_submit(submit, &mut session, tracker_handle, bitcoinrpc_config).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.id, Some(Id::Number(4)));

        // The response should indicate that the share met required difficulty
        assert_eq!(response.result, Some(json!(true)));

        // Verify that the block was not submitted to the mock server
        mock_server.verify().await;
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_submit_a_meets_difficulty_should_submit() {
        let mut session = Session::new(1, None, 2);
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
        let submit: Request = serde_json::from_str(&submit_str).unwrap();

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

        let response = handle_submit(submit, &mut session, tracker_handle, bitcoinrpc_config).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.id, Some(Id::Number(4)));

        // The response should indicate that the share met required difficulty
        assert_eq!(response.result, Some(json!(true)));

        // Verify that the block was not submitted to the mock server
        mock_server.verify().await;
    }
}
