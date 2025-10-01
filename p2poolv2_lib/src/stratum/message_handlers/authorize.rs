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

use crate::shares::chain::chain_store::ChainStore;
use crate::stratum::difficulty_adjuster::DifficultyAdjusterTrait;
use crate::stratum::error::Error;
use crate::stratum::messages::{Message, Response, SetDifficultyNotification, SimpleRequest};
use crate::stratum::server::StratumContext;
use crate::stratum::session::Session;
use crate::stratum::validate_username;
use crate::stratum::work::notify::NotifyCmd;
use std::sync::Arc;
use tracing::debug;

/// Register user in the store and update session with their IDs
fn register_user<D: DifficultyAdjusterTrait>(
    session: &mut Session<D>,
    btcaddress: &str,
    store: Arc<ChainStore>,
) -> Result<(), Error> {
    // Store user and get user_id
    let user_id = store
        .store_user(btcaddress.to_string())
        .map_err(|e| Error::AuthorizationFailure(format!("Failed to store user: {e}")))?;

    session.user_id = Some(user_id);

    Ok(())
}

/// Handle the "mining.authorize" message
/// This function is called when a miner authorizes itself to the Stratum server.
/// It sends a response with the authorization status.
/// The function accepts a mutable reference to a `Session` object, which informs the responses.
/// The session is also updated in response to received messages, if required.
///
/// Some broken implementations of the Stratum protocol send the "mining.authorize" message before "mining.subscribe".
/// We support this by not checking if the session is subscribed before authorizing.
pub(crate) async fn handle_authorize<'a, D: DifficultyAdjusterTrait>(
    message: SimpleRequest<'a>,
    session: &mut Session<D>,
    addr: std::net::SocketAddr,
    ctx: StratumContext,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.authorize message");
    if session.username.is_some() {
        debug!("Client already authorized. No response sent.");
        return Err(Error::AuthorizationFailure(
            "Already authorized".to_string(),
        ));
    }
    let username = match message.params[0].clone() {
        Some(name) => name,
        None => {
            return Err(Error::AuthorizationFailure(
                "Username parameter missing".to_string(),
            ));
        }
    };
    let parsed_username = match validate_username::validate(&username, ctx.network) {
        Ok(validated) => validated,
        Err(e) => {
            return Err(Error::AuthorizationFailure(format!(
                "Invalid username: {e}",
            )));
        }
    };

    session.username = Some(message.params[0].clone().unwrap());
    session.btcaddress = Some(parsed_username.0.to_string());
    session.workername = parsed_username.1.map(|s| s.to_string());
    session.password = message.params[1].clone();

    // Register user in the store
    register_user(session, parsed_username.0, ctx.store)?;

    match ctx
        .metrics
        .increment_worker_count(
            session.btcaddress.clone().unwrap_or_default(),
            session.workername.clone().unwrap_or_default(),
        )
        .await
    {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("Failed to send increment worker count message: {}", e);
        }
    };

    session
        .difficulty_adjuster
        .set_current_difficulty(ctx.start_difficulty);
    let _ = ctx
        .notify_tx
        .send(NotifyCmd::SendToClient {
            client_address: addr,
            clean_jobs: true,
        })
        .await;
    Ok(vec![
        Message::Response(Response::new_ok(message.id, serde_json::json!(true))),
        Message::SetDifficulty(SetDifficultyNotification::new(ctx.start_difficulty)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::stats::metrics;
    use crate::shares::ShareBlock;
    use crate::store::Store;
    use crate::stratum::difficulty_adjuster::DifficultyAdjuster;
    use crate::stratum::messages::Id;
    use crate::stratum::server::StratumContext;
    use crate::stratum::work::tracker::start_tracker_actor;
    use bitcoindrpc::test_utils::setup_mock_bitcoin_rpc;
    use std::net::SocketAddr;
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_handle_authorize_first_time() {
        // Setup
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request = SimpleRequest::new_authorize(
            12345,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            Some("x".to_string()),
        );
        let (notify_tx, mut notify_rx) = mpsc::channel(1);
        let (shares_tx, _shares_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let tracker_handle = start_tracker_actor();
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            shares_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            store,
        };

        // Execute
        let message = handle_authorize(
            request,
            &mut session,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            ctx,
        )
        .await
        .unwrap();

        let (subscribe_response, difficulty_notification) = match &message[..] {
            [
                Message::Response(response),
                Message::SetDifficulty(difficulty_notification),
            ] => (response, difficulty_notification),
            _ => panic!("Expected a Response message"),
        };

        // Verify
        assert_eq!(subscribe_response.id, Some(Id::Number(12345)));
        assert!(subscribe_response.error.is_none());
        assert!(subscribe_response.result.is_some());
        assert_eq!(
            subscribe_response.result.as_ref().unwrap(),
            &serde_json::Value::Bool(true)
        );
        assert_eq!(
            session.username,
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string())
        );
        assert_eq!(
            session.btcaddress.unwrap(),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
        assert_eq!(session.password, Some("x".to_string()));

        // Check that user_id was stored in session
        assert!(session.user_id.is_some(), "user_id should be set");
        assert!(session.user_id.is_some());

        let notify_cmd = notify_rx.try_recv();
        assert!(
            notify_cmd.is_ok(),
            "Notification should be sent to the client after authorization"
        );

        // Check difficulty notification
        assert_eq!(
            difficulty_notification.method, "mining.set_difficulty",
            "Expected method to be 'mining.set_difficulty'"
        );
        assert_eq!(
            difficulty_notification.params[0], 1000,
            "Expected difficulty notification to match pool minimum difficulty"
        );

        match notify_cmd.unwrap() {
            NotifyCmd::SendToClient {
                client_address,
                clean_jobs,
            } => {
                assert_eq!(client_address, SocketAddr::from(([127, 0, 0, 1], 8080)));
                assert!(clean_jobs, "Expected clean_jobs to be true");
            }
            _ => panic!("Expected NotifyCmd::SendToClient"),
        };
    }

    #[tokio::test]
    async fn test_handle_authorize_already_authorized() {
        // Setup
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        session.username = Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string());
        let request = SimpleRequest::new_authorize(
            12345,
            "worker1".to_string(),
            Some("password".to_string()),
        );
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(1);
        let (shares_tx, _shares_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let tracker_handle = start_tracker_actor();
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            shares_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            store,
        };

        // Execute
        let message = handle_authorize(
            request,
            &mut session,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            ctx,
        )
        .await;

        // Verify
        assert!(message.is_err());
        assert_eq!(
            session.username,
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string())
        );
        assert!(session.password.is_none());

        let notify_cmd = notify_rx.try_recv();
        assert!(
            notify_cmd.is_err(),
            "No notification should be sent when already authorized"
        );
    }

    #[test]
    fn test_register_user() {
        // Setup
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let btcaddress = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        // Execute
        let result = register_user(&mut session, btcaddress, store.clone());

        // Verify
        assert!(result.is_ok(), "register_user should succeed");
        assert!(session.user_id.is_some(), "user_id should be set");

        // Verify user were stored correctly
        let user_id = session.user_id.unwrap();

        // Verify user can be retrieved
        let btcaddresses = store
            .store
            .get_btcaddresses_for_user_ids(&[user_id])
            .unwrap();
        assert_eq!(btcaddresses.len(), 1);
        assert_eq!(btcaddresses[0].1, btcaddress);
    }

    #[test]
    fn test_register_same_user_twice() {
        // Setup
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));
        let mut session1 = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let mut session2 = Session::<DifficultyAdjuster>::new(2, 2, None, 0x1fffe000);
        let btcaddress = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        // Execute - register the same user twice
        let result1 = register_user(&mut session1, btcaddress, store.clone());
        let result2 = register_user(&mut session2, btcaddress, store.clone());

        // Verify
        assert!(result1.is_ok(), "First registration should succeed");
        assert!(result2.is_ok(), "Second registration should succeed");

        // Both sessions should have the same user_id
        assert_eq!(
            session1.user_id, session2.user_id,
            "Same user should get the same user_id"
        );
    }

    #[test]
    fn test_register_user_multiple_users() {
        // Setup
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));
        let mut session1 = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let mut session2 = Session::<DifficultyAdjuster>::new(2, 2, None, 0x1fffe000);
        let btcaddress1 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let btcaddress2 = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";

        // Execute - register two different users
        let result1 = register_user(&mut session1, btcaddress1, store.clone());
        let result2 = register_user(&mut session2, btcaddress2, store.clone());

        // Verify
        assert!(result1.is_ok(), "First registration should succeed");
        assert!(result2.is_ok(), "Second registration should succeed");

        // Different users should get different user_ids
        assert!(
            session1.user_id.is_some(),
            "First session should have user_id"
        );
        assert!(
            session2.user_id.is_some(),
            "Second session should have user_id"
        );
        assert_ne!(
            session1.user_id, session2.user_id,
            "Different users should get different user_ids"
        );
    }

    #[tokio::test]
    async fn test_handle_authorize_invalid_username() {
        // Setup
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request = SimpleRequest::new_authorize(
            12345,
            "invalid_address_format".to_string(),
            Some("x".to_string()),
        );
        let (notify_tx, _notify_rx) = mpsc::channel(1);
        let (shares_tx, _shares_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let tracker_handle = start_tracker_actor();
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let temp_dir = tempdir().unwrap();
        let store = Arc::new(ChainStore::new(
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap()),
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));

        let ctx = StratumContext {
            notify_tx,
            tracker_handle,
            bitcoinrpc_config,
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            shares_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            store,
        };

        // Execute
        let result = handle_authorize(
            request,
            &mut session,
            SocketAddr::from(([127, 0, 0, 1], 8080)),
            ctx,
        )
        .await;

        // Verify
        assert!(result.is_err(), "Should fail with invalid username");
        if let Err(Error::AuthorizationFailure(msg)) = result {
            assert!(
                msg.contains("Invalid username"),
                "Expected error message to mention invalid username"
            );
        } else {
            panic!("Expected AuthorizationFailure error");
        }

        // Session should not be updated
        assert!(
            session.username.is_none(),
            "Username should not be set for invalid address"
        );
        assert!(
            session.btcaddress.is_none(),
            "BTC address should not be set for invalid address"
        );
        assert!(
            session.workername.is_none(),
            "Worker name should not be set for invalid address"
        );
        assert!(
            session.password.is_none(),
            "Password should not be set for invalid address"
        );

        // Check that user_id and worker_id remain None
        assert!(
            session.user_id.is_none(),
            "user_id should remain None for invalid username"
        );
        assert!(
            session.worker_id.is_none(),
            "worker_id should remain None for invalid username"
        );
    }
}
