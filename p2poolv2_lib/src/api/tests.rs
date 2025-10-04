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
    use crate::accounting::simple_pplns::SimplePplnsShare;
    use crate::api::handlers;
    use crate::api::models::ApiState;
    use crate::config::Parsed;
    use crate::config::StratumConfig;
    use crate::shares::ShareBlock;
    use crate::shares::chain::chain_store::ChainStore;
    use crate::store::Store;
    use crate::stratum::work::block_template::BlockTemplate;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::tempdir;
    use toml;
    use tower::ServiceExt;

    async fn create_test_api_state() -> ApiState {
        let temp_dir = tempdir().unwrap();
        let store =
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());
        let chain_store = Arc::new(ChainStore::new(
            store.clone(),
            ShareBlock::build_genesis_for_network(bitcoin::Network::Signet),
        ));

        // Add some test shares
        let user_id = chain_store
            .store
            .add_user("test_address".to_string())
            .unwrap();
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
            previousblockhash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
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

        let toml_str = r#"
            hostname = "127.0.0.1"
            port = 3333
            start_difficulty = 1
            minimum_difficulty = 1
            maximum_difficulty = 1000
            zmqpubhashblock = "tcp://127.0.0.1:28332"
            bootstrap_address = "tb1qyazxde6558qj6z3d9np5e6msmrspwpf6k0qggk"
            network = "signet"
            version_mask = "20000000"
            difficulty_multiplier = 1.0
            "#;

        let mut config: StratumConfig<Parsed> = toml::from_str(toml_str).unwrap();
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
        let app = Router::new().route("/health", get(handlers::health_check));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
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

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            app.oneshot(
                Request::builder()
                    .uri("/api/shares")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("test_get_shares timed out - likely deadlock in handler")
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_block_template() {
        let state = create_test_api_state().await;
        let app = Router::new()
            .route("/api/block-template", get(handlers::get_block_template))
            .with_state(state);

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            app.oneshot(
                Request::builder()
                    .uri("/api/block-template")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("test_get_block_template timed out - likely deadlock in handler")
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_pplns_distribution() {
        let state = create_test_api_state().await;
        let app = Router::new()
            .route(
                "/api/pplns-distribution",
                get(handlers::get_pplns_distribution),
            )
            .with_state(state);

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            app.oneshot(
                Request::builder()
                    .uri("/api/pplns-distribution")
                    .body(Body::empty())
                    .unwrap(),
            ),
        )
        .await
        .expect("test_get_pplns_distribution timed out - likely deadlock in handler")
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
