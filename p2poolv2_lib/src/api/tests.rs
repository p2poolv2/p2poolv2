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

#[cfg(test)]
mod tests {
    use super::handlers;
    use super::models::ApiState;
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use crate::config::StratumConfig;
    use crate::shares::ShareBlock;
    use crate::shares::chain::chain_store::ChainStore;
    use crate::store::Store;
    use crate::stratum::work::block_template::BlockTemplate;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    async fn create_test_api_state() -> ApiState {
        let temp_dir = tempdir().unwrap();
        let store = Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());
        let chain_store = Arc::new(ChainStore::new(
            store,
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));

        // Add some test shares
        let user_id = chain_store.store.add_user("test_address".to_string()).unwrap();
        let share = SimplePplnsShare::new(
            user_id,
            100,
            "test_address".to_string(),
            "test_worker".to_string(),
            1640995200, // timestamp
            "test_job".to_string(),
            "test_extra".to_string(),
            "test_nonce".to_string(),
        );
        chain_store.store.add_pplns_share(share).unwrap();

        // Create a test block template
        let template = BlockTemplate {
            version: 536870912,
            rules: vec!["segwit".to_string()],
            vbavailable: HashMap::new(),
            vbrequired: 0,
            previousblockhash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            transactions: vec![],
            coinbaseaux: HashMap::new(),
            coinbasevalue: 5000000000,
            longpollid: "test_longpoll".to_string(),
            target: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            mintime: 1640995200,
            mutable: vec![],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1640995200,
            bits: "1d00ffff".to_string(),
            height: 1,
            default_witness_commitment: None,
        };

        let current_template = Arc::new(tokio::sync::RwLock::new(Some(template)));

        // Create minimal config
        let mut config = StratumConfig::default();
        config.network = bitcoin::Network::Signet;
        config.difficulty_multiplier = 1.0;

        ApiState {
            chain_store,
            current_template,
            config,
        }
    }

    #[tokio::test]
    async fn test_health_check() {
        let app = Router::new()
            .route("/health", get(handlers::health_check));

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_shares() {
        let state = create_test_api_state().await;
        let app = Router::new()
            .route("/api/shares", get(handlers::get_shares))
            .with_state(state);

        let response = app
            .oneshot(Request::builder().uri("/api/shares").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_block_template() {
        let state = create_test_api_state().await;
        let app = Router::new()
            .route("/api/block-template", get(handlers::get_block_template))
            .with_state(state);

        let response = app
            .oneshot(Request::builder().uri("/api/block-template").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_pplns_distribution() {
        let state = create_test_api_state().await;
        let app = Router::new()
            .route("/api/pplns-distribution", get(handlers::get_pplns_distribution))
            .with_state(state);

        let response = app
            .oneshot(Request::builder().uri("/api/pplns-distribution").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}