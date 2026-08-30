// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

use crate::address::{Address as P2PoolAddress, AddressError};
use crate::config::PoolMode;
use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::stratum::{
    difficulty_adjuster::DifficultyAdjusterTrait,
    error::{Error, StratumErrorCode},
    messages::{Id, Message, Response, SetDifficultyNotification, SimpleRequest},
    parse_password::parse_password,
    server::StratumContext,
    session::Session,
    validate_username,
};
use tracing::debug;

/// Register user in the store and update session with their IDs
async fn register_user<D: DifficultyAdjusterTrait>(
    session: &mut Session<D>,
    btcaddress: &str,
    chain_store_handle: ChainStoreHandle,
) -> Result<(), Error> {
    // Store user and get user_id
    let user_id = chain_store_handle
        .add_user(btcaddress.to_string())
        .await
        .map_err(|e| Error::AuthorizationFailure(format!("Failed to store user: {e}")))?;

    session.user_id = Some(user_id);

    Ok(())
}

/// Resolve which share chain address owns this miner's shares.
///
/// The node's configured address wins: when set, it owns every share on the
/// pool and a miner naming a different owner from the node is a conflict.
/// Two rules drive the table -- never derive an address, and never silently
/// substitute one for another, because a miner who set a miner address must
/// be told rather than have shares assigned elsewhere.
///
/// Hydrapool builds no share commitment, so no address is needed there.
fn resolve_share_address(
    configured: Option<P2PoolAddress>,
    supplied: Option<&Result<P2PoolAddress, AddressError>>,
    network: bitcoin::Network,
    mode: PoolMode,
) -> Result<Option<P2PoolAddress>, String> {
    if mode == PoolMode::Hydrapool {
        return Ok(None);
    }

    match (configured, supplied) {
        (Some(configured), Some(Ok(supplied))) if *supplied != configured => Err(format!(
            "Share address {supplied} conflicts with the pool's configured {configured}. Remove p2p= from the password, or set it to the node address."
        )),
        (Some(configured), Some(Err(error))) => Err(format!(
            "Could not read the p2p= share address ({error}). Remove it to use the node's address {configured}, or correct it. Note p2p=<address> is 71 characters and some miner firmware truncates the password field."
        )),
        (Some(configured), _) => Ok(Some(configured)),
        (None, Some(Ok(supplied))) => supplied
            .require_network(network)
            .map(Some)
            .map_err(|error| format!("Share address is not usable on this pool: {error}")),
        (None, Some(Err(error))) => Err(format!(
            "Could not read the p2p= share address ({error}). Note p2p=<address> is 71 characters and some miner firmware truncates the password field."
        )),
        (None, None) => Err(
            "This pool needs a share chain address. Set the stratum password to p2p=<address>, which you can generate with `p2poolv2_cli address encode`."
                .to_string(),
        ),
    }
}

/// Send an authorization error, disconnecting on a repeat offence.
///
/// Returning `Err` here instead would close the socket without writing anything
/// (see the message loop in `stratum::server`), leaving the miner with an
/// unexplained disconnect and nothing to diagnose. So the first attempt gets a
/// message and the second, still wrong, drops the connection.
fn reject_authorize<'a, D: DifficultyAdjusterTrait>(
    session: &mut Session<D>,
    id: Option<Id>,
    reason: String,
) -> Result<Vec<Message<'a>>, Error> {
    if session.auth_failed_once {
        return Err(Error::AuthorizationFailure(format!(
            "Second miner address failure. Disconnecting. {reason}"
        )));
    }
    session.auth_failed_once = true;
    debug!("Rejecting authorize: {reason}");
    Ok(vec![Message::Response(
        Response::new_error(id, StratumErrorCode::UnauthorizedWorker).with_message(reason),
    )])
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
    ctx: StratumContext,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.authorize message");
    if session.username.is_some() {
        debug!("Client already authorized. No response sent.");
        return Err(Error::AuthorizationFailure(
            "Already authorized".to_string(),
        ));
    }
    let username = match message.params.first().and_then(|p| p.clone()) {
        Some(name) => name,
        None => {
            return Ok(vec![Message::Response(
                Response::new_error(message.id, StratumErrorCode::UnauthorizedWorker)
                    .with_message("Empty username".to_string()),
            )]);
        }
    };
    let parsed_username =
        match validate_username::validate(&username, ctx.validate_addresses, ctx.network) {
            Ok(validated) => validated,
            Err(_e) => {
                if !session.auth_failed_once {
                    session.auth_failed_once = true;
                    return Ok(vec![Message::Response(
                        Response::new_error(message.id, StratumErrorCode::UnauthorizedWorker)
                            .with_message("Invalid username".to_string()),
                    )]);
                } else {
                    return Err(Error::AuthorizationFailure(
                        "Second invalid username. Disconnecting.".to_string(),
                    ));
                }
            }
        };

    session.username = Some(username.clone());
    session.btcaddress = Some(parsed_username.address_str.to_string());
    session.parsed_address = parsed_username.parsed_address;
    session.workername = parsed_username.worker_name.map(|s| s.to_string());
    session.password = message.params.get(1).and_then(|p| p.clone());

    // Register user in the store
    register_user(session, parsed_username.address_str, ctx.chain_store_handle).await?;

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

    // Parse once; the password carries both the difficulty hint and the share
    // chain address. ParsedPassword owns its values, so this does not hold a
    // borrow of the session.
    let parsed_password = session.password.as_deref().map(parse_password);

    let supplied_address = parsed_password
        .as_ref()
        .and_then(|parsed| parsed.miner_address.as_ref());

    session.miner_address =
        match resolve_share_address(ctx.miner_address, supplied_address, ctx.network, ctx.mode) {
            Ok(address) => address,
            Err(reason) => return reject_authorize(session, message.id, reason),
        };

    let start_difficulty = match parsed_password.and_then(|parsed| parsed.difficulty) {
        Some(requested_difficulty) => {
            let constrained = session
                .difficulty_adjuster
                .apply_difficulty_constraints(requested_difficulty, Some(requested_difficulty));
            debug!(
                "Password difficulty override: requested={}, constrained={}",
                requested_difficulty, constrained
            );
            constrained
        }
        None => ctx.start_difficulty,
    };

    session
        .difficulty_adjuster
        .set_current_difficulty(start_difficulty);
    // After authorization, the connection handler will pick up the current
    // prepared template from the watch channel and send the first notify.
    // We set a flag so handle_connection knows to send the initial notify.
    session.needs_first_notify = true;

    Ok(vec![
        Message::Response(Response::new_ok(message.id, serde_json::json!(true))),
        Message::SetDifficulty(SetDifficultyNotification::new(start_difficulty)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::stats::metrics;
    use crate::stratum::difficulty_adjuster::DifficultyAdjuster;
    use crate::stratum::server::PoolMode;
    use crate::stratum::server::StratumContext;
    use crate::stratum::work::tracker::start_tracker_actor;
    use crate::test_utils::make_test_share_address;
    use crate::test_utils::setup_test_chain_store_handle;
    use bitcoindrpc::BitcoindRpcClient;
    use bitcoindrpc::test_utils::setup_mock_bitcoin_rpc;
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
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, bitcoin::Network::Testnet4)),
        };

        // Execute
        let message = handle_authorize(request, &mut session, ctx).await.unwrap();

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

        // Verify the session's needs_first_notify flag was set
        assert!(
            session.needs_first_notify,
            "needs_first_notify should be set after authorization"
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
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let tracker_handle = start_tracker_actor();
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, bitcoin::Network::Testnet4)),
        };

        // Execute
        let message = handle_authorize(request, &mut session, ctx).await;

        // Verify
        assert!(message.is_err());
        assert_eq!(
            session.username,
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string())
        );
        assert!(session.password.is_none());
    }

    #[tokio::test]
    async fn test_register_user() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let btcaddress = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        // Execute
        let result = register_user(&mut session, btcaddress, chain_store_handle.clone()).await;

        // Verify
        assert!(result.is_ok(), "register_user should succeed");
        assert!(session.user_id.is_some(), "user_id should be set");

        // Verify user were stored correctly
        let user_id = session.user_id.unwrap();

        // Verify user can be retrieved
        let btcaddresses = chain_store_handle
            .get_btcaddresses_for_user_ids(&[user_id])
            .unwrap();
        assert_eq!(btcaddresses.len(), 1);
        assert_eq!(btcaddresses[0].1, btcaddress);
    }

    #[tokio::test]
    async fn test_register_same_user_twice() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let mut session1 = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let mut session2 = Session::<DifficultyAdjuster>::new(2, 2, None, 0x1fffe000);
        let btcaddress = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        // Execute - register the same user twice
        let result1 = register_user(&mut session1, btcaddress, chain_store_handle.clone()).await;
        let result2 = register_user(&mut session2, btcaddress, chain_store_handle).await;

        // Verify
        assert!(result1.is_ok(), "First registration should succeed");
        assert!(result2.is_ok(), "Second registration should succeed");

        // Both sessions should have the same user_id
        assert_eq!(
            session1.user_id, session2.user_id,
            "Same user should get the same user_id"
        );
    }

    #[tokio::test]
    async fn test_register_user_multiple_users() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let mut session1 = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let mut session2 = Session::<DifficultyAdjuster>::new(2, 2, None, 0x1fffe000);
        let btcaddress1 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let btcaddress2 = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";

        // Execute - register two different users
        let result1 = register_user(&mut session1, btcaddress1, chain_store_handle.clone()).await;
        let result2 = register_user(&mut session2, btcaddress2, chain_store_handle).await;

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
    async fn test_handle_authorize_invalid_username_first_attempt() {
        // Setup
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request = SimpleRequest::new_authorize(
            12345,
            "invalid_address_format".to_string(),
            Some("x".to_string()),
        );
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let tracker_handle = start_tracker_actor();
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, bitcoin::Network::Testnet4)),
        };

        // Execute
        let result = handle_authorize(request, &mut session, ctx).await;

        // Verify - first invalid username should return Ok with error response
        assert!(
            result.is_ok(),
            "First invalid username should return Ok with error response"
        );
        let messages = result.unwrap();
        assert_eq!(messages.len(), 1, "Should return one message");
        match &messages[0] {
            Message::Response(response) => {
                assert!(response.error.is_some(), "Response should have an error");
                let error = response.error.as_ref().unwrap();
                assert_eq!(error.code, 24, "Error code should be 24");
                assert_eq!(
                    error.message, "Invalid username",
                    "Error message should be 'Invalid username'"
                );
            }
            _ => panic!("Expected Response message"),
        }

        // Session should mark auth_failed_once as true
        assert!(
            session.auth_failed_once,
            "auth_failed_once should be set to true after first invalid username"
        );

        // Session should not be updated with user data
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

    #[tokio::test]
    async fn test_handle_authorize_with_password_difficulty_override() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request = SimpleRequest::new_authorize(
            12345,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            Some("d=500".to_string()),
        );
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, bitcoin::Network::Testnet4)),
        };

        let messages = handle_authorize(request, &mut session, ctx).await.unwrap();

        assert_eq!(session.password, Some("d=500".to_string()));
        assert_eq!(
            session.difficulty_adjuster.get_current_difficulty(),
            500,
            "Difficulty should be overridden to 500 from password"
        );

        if let Message::SetDifficulty(notification) = &messages[1] {
            assert_eq!(
                notification.params[0], 500,
                "SetDifficulty notification should use password difficulty"
            );
        } else {
            panic!("Expected SetDifficulty message");
        }
    }

    #[tokio::test]
    async fn test_handle_authorize_password_difficulty_respects_minimum() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 100, None, 0x1fffe000);
        let request = SimpleRequest::new_authorize(
            12345,
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            Some("d=50".to_string()),
        );
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 100,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, bitcoin::Network::Testnet4)),
        };

        let messages = handle_authorize(request, &mut session, ctx).await.unwrap();

        assert_eq!(
            session.difficulty_adjuster.get_current_difficulty(),
            100,
            "Difficulty should be clamped to pool minimum of 100"
        );

        if let Message::SetDifficulty(notification) = &messages[1] {
            assert_eq!(
                notification.params[0], 100,
                "SetDifficulty notification should use clamped difficulty"
            );
        } else {
            panic!("Expected SetDifficulty message");
        }
    }

    #[tokio::test]
    async fn test_handle_authorize_invalid_username_second_attempt() {
        // Setup - session with auth_failed_once already true
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        session.auth_failed_once = true;
        let request = SimpleRequest::new_authorize(
            12345,
            "invalid_address_format".to_string(),
            Some("x".to_string()),
        );
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let tracker_handle = start_tracker_actor();
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: Some(2),
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, bitcoin::Network::Testnet4)),
        };

        // Execute
        let result = handle_authorize(request, &mut session, ctx).await;

        // Verify - second invalid username should return Err
        assert!(result.is_err(), "Second invalid username should return Err");
        if let Err(Error::AuthorizationFailure(msg)) = result {
            assert!(
                msg.contains("Second invalid username"),
                "Expected error message to mention second invalid username"
            );
        } else {
            panic!("Expected AuthorizationFailure error");
        }

        // Session should not be updated with user data
        assert!(
            session.username.is_none(),
            "Username should not be set for invalid address"
        );
        assert!(
            session.btcaddress.is_none(),
            "BTC address should not be set for invalid address"
        );
    }

    #[tokio::test]
    async fn test_handle_authorize_empty_params_returns_error_not_panic() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request = SimpleRequest {
            id: Some(Id::Number(1)),
            method: std::borrow::Cow::Owned("mining.authorize".to_string()),
            params: std::borrow::Cow::Owned(vec![]),
        };
        let (emissions_tx, _) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let tracker_handle = start_tracker_actor();
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, bitcoin::Network::Testnet4)),
        };

        let result = handle_authorize(request, &mut session, ctx).await;
        assert!(result.is_ok());
        let messages = result.unwrap();
        let response = match &messages[..] {
            [Message::Response(r)] => r,
            _ => panic!("expected Response"),
        };
        let err = response.error.as_ref().unwrap();
        assert_eq!(err.code, 24, "should be UnauthorizedWorker (code 24)");
        assert_eq!(err.message, "Empty username");
    }
}

#[cfg(test)]
mod p2p_miner_address_tests {
    use super::*;
    use crate::accounting::stats::metrics;
    use crate::stratum::difficulty_adjuster::DifficultyAdjuster;
    use crate::stratum::server::PoolMode;
    use crate::stratum::server::StratumContext;
    use crate::stratum::work::tracker::start_tracker_actor;
    use crate::test_utils::setup_test_chain_store_handle;
    use bitcoindrpc::BitcoindRpcClient;
    use bitcoindrpc::test_utils::setup_mock_bitcoin_rpc;
    use tokio::sync::mpsc;

    /// BIP086 tweak of PUBKEY_G on testnet4.
    const SHARE_ADDRESS: &str =
        "tp2pool1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sss3v29v";
    const BITCOIN_ADDRESS: &str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

    #[tokio::test]
    async fn authorize_stores_the_share_address_from_the_password() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request = SimpleRequest::new_authorize(
            12345,
            BITCOIN_ADDRESS.to_string(),
            Some(format!("p2p={SHARE_ADDRESS}")),
        );
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet4,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        handle_authorize(request, &mut session, ctx).await.unwrap();

        assert_eq!(
            session.miner_address.map(|address| address.to_string()),
            Some(SHARE_ADDRESS.to_string())
        );
        // The two addresses are on different chains and must not be conflated.
        assert_eq!(session.btcaddress, Some(BITCOIN_ADDRESS.to_string()));
        assert!(session.parsed_address.is_some());
    }

    #[tokio::test]
    async fn authorize_without_a_p2p_option_leaves_the_share_address_unset() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request =
            SimpleRequest::new_authorize(12345, BITCOIN_ADDRESS.to_string(), Some("x".to_string()));
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet4,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        handle_authorize(request, &mut session, ctx).await.unwrap();

        assert!(session.miner_address.is_none());
        assert_eq!(session.btcaddress, Some(BITCOIN_ADDRESS.to_string()));
        assert!(session.parsed_address.is_some());
    }

    #[tokio::test]
    async fn authorize_with_no_password_at_all_leaves_the_share_address_unset() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request = SimpleRequest::new_authorize(12345, BITCOIN_ADDRESS.to_string(), None);
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet4,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        handle_authorize(request, &mut session, ctx).await.unwrap();

        assert!(session.miner_address.is_none());
        assert_eq!(session.btcaddress, Some(BITCOIN_ADDRESS.to_string()));
        assert!(session.parsed_address.is_some());
    }

    /// A malformed p2p= address is a rejection, not a silent drop: the miner
    /// named an owner we cannot honour, and assigning their shares elsewhere
    /// would be worse than refusing the connection.
    #[tokio::test]
    async fn authorize_with_a_malformed_share_address_is_rejected() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request = SimpleRequest::new_authorize(
            12345,
            BITCOIN_ADDRESS.to_string(),
            Some("p2p=not-a-share-address".to_string()),
        );
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet4,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        let messages = handle_authorize(request, &mut session, ctx).await.unwrap();

        assert!(session.miner_address.is_none());
        assert!(
            session.auth_failed_once,
            "a rejected address must arm the two-strikes disconnect"
        );

        if let Message::Response(response) = &messages[0] {
            let message_text = format!("{:?}", response.error);
            assert!(
                response.error.is_some(),
                "a malformed share address must be reported to the miner"
            );
            assert!(
                message_text.contains("p2p="),
                "the error must name the option the miner has to fix: {message_text}"
            );
        } else {
            panic!("Expected a Response message");
        }
    }

    /// A miner supplying both options must get both. This is the regression
    /// guard for parsing the password once and using two of its fields.
    #[tokio::test]
    async fn share_address_and_difficulty_are_both_applied_from_one_password() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, 0x1fffe000);
        let request = SimpleRequest::new_authorize(
            12345,
            BITCOIN_ADDRESS.to_string(),
            Some(format!("p2p={SHARE_ADDRESS},d=500")),
        );
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let (_mock_rpc_server, bitcoinrpc_config) = setup_mock_bitcoin_rpc().await;
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics_handle = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let tracker_handle = start_tracker_actor();

        let ctx = StratumContext {
            tracker_handle,
            bitcoindrpc_client: BitcoindRpcClient::new(
                &bitcoinrpc_config.url,
                &bitcoinrpc_config.username,
                &bitcoinrpc_config.password,
            )
            .unwrap(),
            start_difficulty: 1000,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: false,
            validate_addresses: true,
            emissions_tx,
            network: bitcoin::network::Network::Testnet4,
            metrics: metrics_handle,
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: None,
        };

        handle_authorize(request, &mut session, ctx).await.unwrap();

        assert_eq!(
            session.miner_address.map(|address| address.to_string()),
            Some(SHARE_ADDRESS.to_string())
        );
        assert_eq!(session.btcaddress, Some(BITCOIN_ADDRESS.to_string()));
        assert!(session.parsed_address.is_some());
        assert_eq!(session.difficulty_adjuster.get_current_difficulty(), 500);
    }
}

/// Direct coverage of the share address resolution table.
///
/// These drive the pure function rather than `handle_authorize`, so every arm
/// is reachable without a StratumContext, a store and a mock rpc server.
#[cfg(test)]
mod resolve_share_address_tests {
    use super::*;
    use crate::test_utils::make_test_share_address;
    use bitcoin::Network;

    fn configured() -> P2PoolAddress {
        make_test_share_address(1, Network::Signet)
    }

    fn different() -> P2PoolAddress {
        make_test_share_address(2, Network::Signet)
    }

    fn unparseable() -> Result<P2PoolAddress, AddressError> {
        Err("not-a-share-address".parse::<P2PoolAddress>().unwrap_err())
    }

    #[test]
    fn hydrapool_needs_no_address_at_all() {
        let resolved =
            resolve_share_address(None, None, Network::Signet, PoolMode::Hydrapool).unwrap();
        assert!(resolved.is_none());
    }

    /// Hydrapool builds no share commitment, so a supplied address is not an
    /// error there, it is simply unused.
    #[test]
    fn hydrapool_ignores_a_supplied_address() {
        let supplied = Ok(configured());
        let resolved =
            resolve_share_address(None, Some(&supplied), Network::Signet, PoolMode::Hydrapool)
                .unwrap();
        assert!(resolved.is_none());
    }

    #[test]
    fn hydrapool_ignores_a_conflict_that_would_fail_in_p2poolv2() {
        let supplied = Ok(different());
        let resolved = resolve_share_address(
            Some(configured()),
            Some(&supplied),
            Network::Signet,
            PoolMode::Hydrapool,
        )
        .unwrap();
        assert!(resolved.is_none());
    }

    #[test]
    fn configured_address_is_used_when_the_password_has_none() {
        let resolved = resolve_share_address(
            Some(configured()),
            None,
            Network::Signet,
            PoolMode::P2poolv2,
        )
        .unwrap();
        assert_eq!(resolved, Some(configured()));
    }

    #[test]
    fn supplied_address_matching_the_configured_one_is_accepted() {
        let supplied = Ok(configured());
        let resolved = resolve_share_address(
            Some(configured()),
            Some(&supplied),
            Network::Signet,
            PoolMode::P2poolv2,
        )
        .unwrap();
        assert_eq!(resolved, Some(configured()));
    }

    /// The error has to name both addresses: the fix could belong to either the
    /// miner or the operator, and neither can act on "mismatch" alone.
    #[test]
    fn supplied_address_conflicting_with_the_configured_one_is_rejected() {
        let supplied = Ok(different());
        let reason = resolve_share_address(
            Some(configured()),
            Some(&supplied),
            Network::Signet,
            PoolMode::P2poolv2,
        )
        .unwrap_err();

        assert!(reason.contains(&configured().to_string()), "{reason}");
        assert!(reason.contains(&different().to_string()), "{reason}");
    }

    /// Unparseable while the pool has one configured is a conflict, not a
    /// fallback: the miner named an owner we cannot check against the pool's,
    /// and silently using the pool address would assign their shares elsewhere.
    #[test]
    fn unparseable_supplied_address_is_rejected_even_with_a_configured_one() {
        let supplied = unparseable();
        let reason = resolve_share_address(
            Some(configured()),
            Some(&supplied),
            Network::Signet,
            PoolMode::P2poolv2,
        )
        .unwrap_err();

        assert!(reason.contains("p2p="), "{reason}");
        assert!(reason.contains(&configured().to_string()), "{reason}");
    }

    #[test]
    fn supplied_address_is_used_when_the_node_configured_none() {
        let supplied = Ok(configured());
        let resolved =
            resolve_share_address(None, Some(&supplied), Network::Signet, PoolMode::P2poolv2)
                .unwrap();
        assert_eq!(resolved, Some(configured()));
    }

    /// A miner-supplied address is network checked here, unlike a configured
    /// one which config parse already validated.
    #[test]
    fn supplied_address_for_another_network_is_rejected() {
        let supplied = Ok(make_test_share_address(1, Network::Testnet4));
        let reason =
            resolve_share_address(None, Some(&supplied), Network::Signet, PoolMode::P2poolv2)
                .unwrap_err();

        assert!(reason.contains("not usable on this pool"), "{reason}");
    }

    #[test]
    fn unparseable_supplied_address_without_a_configured_one_is_rejected() {
        let supplied = unparseable();
        let reason =
            resolve_share_address(None, Some(&supplied), Network::Signet, PoolMode::P2poolv2)
                .unwrap_err();

        assert!(reason.contains("p2p="), "{reason}");
    }

    /// The message has to tell a miner what to do, not merely that something is
    /// missing, since this is the first thing a new miner hits.
    #[test]
    fn no_address_from_either_source_is_rejected() {
        let reason =
            resolve_share_address(None, None, Network::Signet, PoolMode::P2poolv2).unwrap_err();

        assert!(reason.contains("p2p="), "{reason}");
        assert!(reason.contains("address encode"), "{reason}");
    }
}
