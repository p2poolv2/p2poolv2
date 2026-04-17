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

//! Testnet4 min-difficulty block filtering with periodic reconsider.
//!
//! During the testnet4 timing attack, attackers exploit the 20-minute rule to
//! cheaply mine blocks at the network's minimum difficulty (compact bits
//! `0x1d00ffff`). The [`Testnet4Mitigation`] struct invalidates such blocks at
//! the tip before serving a block template to local miners, so we build on top
//! of a non-attack ancestor.
//!
//! To prevent the chain from falling permanently behind, a background task
//! periodically calls `reconsiderblock` on the deepest invalidated hash.
//! Because `reconsiderblock` clears the invalid flag on the target and all its
//! descendants, one call restores the entire chain and lets bitcoind reorg to
//! the most-work tip.

use crate::stratum::work::block_template::BlockTemplate;
use crate::stratum::work::gbt::fetch_template_directly;
use bitcoindrpc::BitcoindRpcClient;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio::time::{Duration, interval};
use tracing::{info, warn};

/// Compact `bits` value for testnet's pow_limit. Any block at the tip with
/// this value is a 20-minute-rule min-difficulty block on testnet4.
const MIN_DIFFICULTY_BITS: u32 = 0x1d00ffff;

/// Cap on the number of consecutive ancestor blocks we will invalidate in a
/// single template fetch. Bounds RPC traffic and prevents runaway invalidation
/// if the entire visible tail of the chain is min-difficulty.
const MAX_INVALIDATIONS_PER_TEMPLATE: usize = 100;

/// Interval between periodic `reconsiderblock` sweeps (30 minutes).
const RECONSIDER_INTERVAL_SECS: u64 = 1800;

/// Testnet4 timing-attack mitigation state.
///
/// Holds a bitcoind RPC client, the network identifier, and the deepest
/// invalidated block hash from the most recent invalidation run.
/// Wrapped in `Arc` and shared between the GBT task (which calls
/// [`fetch_block_template`]) and the background reconsider task.
pub struct Testnet4Mitigation {
    bitcoind: BitcoindRpcClient,
    network: bitcoin::Network,
    /// The deepest block we invalidated in the most recent run.  When
    /// reconsider is called with this single hash, all descendants
    /// are also reconsidered by bitcoind.
    deepest_invalidated: std::sync::Mutex<Option<bitcoin::BlockHash>>,
}

impl Testnet4Mitigation {
    /// Create a new mitigation instance for the given network.
    pub fn new(bitcoind: BitcoindRpcClient, network: bitcoin::Network) -> Self {
        Self {
            bitcoind,
            network,
            deepest_invalidated: std::sync::Mutex::new(None),
        }
    }

    /// Walk back from the tip invalidating min-difficulty blocks, then fetch a
    /// fresh block template.
    ///
    /// Stops after the first non-min-difficulty tip is reached, or after
    /// `MAX_INVALIDATIONS_PER_TEMPLATE` invalidations, whichever comes first.
    /// Always proceeds to fetch and return a template from bitcoind, even if
    /// the invalidation cap was hit (best-effort mitigation).
    ///
    /// Stores only the deepest (last) invalidated hash for later reconsider.
    pub async fn fetch_block_template(
        &self,
    ) -> Result<BlockTemplate, Box<dyn std::error::Error + Send + Sync>> {
        let mut invalidated = 0usize;
        let mut last_invalidated_hash: Option<bitcoin::BlockHash> = None;
        while invalidated < MAX_INVALIDATIONS_PER_TEMPLATE {
            let tip = self.bitcoind.getbestblockhash().await?;
            let bits = self.bitcoind.getblockheader_bits(&tip).await?;
            if bits != MIN_DIFFICULTY_BITS {
                break;
            }
            self.bitcoind.invalidateblock(&tip).await?;
            info!("Invalidated min-difficulty tip {tip} (bits={bits:#x})");
            last_invalidated_hash = Some(tip);
            invalidated += 1;
        }
        if invalidated == MAX_INVALIDATIONS_PER_TEMPLATE {
            warn!(
                "Reached invalidation cap of {} for a single template fetch; \
                 proceeding with current tip",
                MAX_INVALIDATIONS_PER_TEMPLATE
            );
        }
        if let Some(hash) = last_invalidated_hash {
            *self.deepest_invalidated.lock().unwrap() = Some(hash);
        }
        fetch_template_directly(&self.bitcoind, self.network).await
    }

    /// Spawn a background task that calls `reconsiderblock` on the deepest
    /// invalidated hash every 30 minutes.
    ///
    /// After reconsidering, bitcoind re-evaluates the entire subtree and
    /// automatically reorgs to the most-work chain if the restored chain wins.
    /// The next GBT poll will re-invalidate any min-diff blocks at the new tip.
    pub fn start_reconsider_task(self: &Arc<Self>) -> JoinHandle<()> {
        let mitigation = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(RECONSIDER_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let hash = mitigation.deepest_invalidated.lock().unwrap().take();
                if let Some(block_hash) = hash {
                    info!("Reconsidering previously invalidated block {block_hash}");
                    match mitigation.bitcoind.reconsiderblock(&block_hash).await {
                        Ok(()) => {
                            info!("Successfully reconsidered block {block_hash}");
                        }
                        Err(error) => {
                            warn!("Failed to reconsider block {block_hash}: {error}");
                        }
                    }
                }
            }
        })
    }

    /// Read the current deepest invalidated hash (for testing).
    #[cfg(test)]
    fn deepest_invalidated(&self) -> Option<bitcoin::BlockHash> {
        *self.deepest_invalidated.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use bitcoindrpc::test_utils::{mock_method, setup_mock_bitcoin_rpc};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    /// Test responder that hands back a sequence of canned `bits` values
    /// (one per `getblockheader` call), tracking how many times it was hit.
    struct SequencedHeaderResponder {
        bits_sequence: Vec<u32>,
        call_count: Arc<AtomicUsize>,
    }

    impl Respond for SequencedHeaderResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let index = self.call_count.fetch_add(1, Ordering::SeqCst);
            let bits = if index < self.bits_sequence.len() {
                self.bits_sequence[index]
            } else {
                *self.bits_sequence.last().unwrap()
            };
            ResponseTemplate::new(200).set_body_json(json!({
                "result": {
                    "hash": "00".repeat(32),
                    "height": 100,
                    "bits": format!("{bits:08x}"),
                    "version": 1,
                    "time": 1610000000,
                },
                "error": null,
                "id": 0,
            }))
        }
    }

    /// Test responder that returns a sequence of distinct tip hashes so the
    /// invalidation loop sees a "new" tip each time after invalidating.
    struct SequencedTipResponder {
        call_count: Arc<AtomicUsize>,
    }

    impl Respond for SequencedTipResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let index = self.call_count.fetch_add(1, Ordering::SeqCst);
            // Encode the index into the tail of the hash for uniqueness.
            let mut hash_bytes = [0u8; 32];
            hash_bytes[24..32].copy_from_slice(&(index as u64).to_be_bytes());
            let hash = BlockHash::from_byte_array(hash_bytes);
            ResponseTemplate::new(200).set_body_json(json!({
                "result": hash.to_string(),
                "error": null,
                "id": 0,
            }))
        }
    }

    /// Build a minimal valid getblocktemplate response body.
    fn template_response_body() -> serde_json::Value {
        json!({
            "version": 536870912,
            "rules": ["segwit"],
            "vbavailable": {},
            "vbrequired": 0,
            "previousblockhash": "00".repeat(32),
            "transactions": [],
            "coinbaseaux": {},
            "coinbasevalue": 5000000000u64,
            "longpollid": "id",
            "target": "00".repeat(32),
            "mintime": 1610000000,
            "mutable": ["time", "transactions", "prevblock"],
            "noncerange": "00000000ffffffff",
            "sigoplimit": 80000,
            "sizelimit": 4000000,
            "weightlimit": 4000000,
            "curtime": 1610000000,
            "bits": "1a01f56e",
            "height": 1,
        })
    }

    async fn mount_tip_sequence(server: &MockServer, counter: Arc<AtomicUsize>) {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({ "method": "getbestblockhash" })))
            .respond_with(SequencedTipResponder {
                call_count: counter,
            })
            .mount(server)
            .await;
    }

    async fn mount_header_sequence(
        server: &MockServer,
        counter: Arc<AtomicUsize>,
        bits_sequence: Vec<u32>,
    ) {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({ "method": "getblockheader" })))
            .respond_with(SequencedHeaderResponder {
                bits_sequence,
                call_count: counter,
            })
            .mount(server)
            .await;
    }

    async fn mount_invalidate_counter(server: &MockServer, counter: Arc<AtomicUsize>) {
        struct CountingResponder {
            counter: Arc<AtomicUsize>,
        }
        impl Respond for CountingResponder {
            fn respond(&self, _request: &Request) -> ResponseTemplate {
                self.counter.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(json!({
                    "result": null,
                    "error": null,
                    "id": 0,
                }))
            }
        }
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({ "method": "invalidateblock" })))
            .respond_with(CountingResponder { counter })
            .mount(server)
            .await;
    }

    async fn mount_reconsider(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_partial_json(json!({ "method": "reconsiderblock" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "result": null,
                "error": null,
                "id": 0,
            })))
            .mount(server)
            .await;
    }

    async fn mount_template(server: &MockServer) {
        mock_method(
            server,
            "getblocktemplate",
            json!([{
                "capabilities": ["coinbasetxn", "coinbase/append", "workid"],
                "rules": ["segwit"],
            }]),
            template_response_body().to_string(),
        )
        .await;
    }

    fn mitigation_for(config: &bitcoindrpc::BitcoinRpcConfig) -> Testnet4Mitigation {
        let client =
            BitcoindRpcClient::new(&config.url, &config.username, &config.password).unwrap();
        Testnet4Mitigation::new(client, bitcoin::Network::Bitcoin)
    }

    #[tokio::test]
    async fn fetch_block_template_no_invalidation() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        let tip_counter = Arc::new(AtomicUsize::new(0));
        let header_counter = Arc::new(AtomicUsize::new(0));
        let invalidate_counter = Arc::new(AtomicUsize::new(0));

        mount_tip_sequence(&server, tip_counter.clone()).await;
        mount_header_sequence(&server, header_counter.clone(), vec![0x1a01f56e]).await;
        mount_invalidate_counter(&server, invalidate_counter.clone()).await;
        mount_template(&server).await;

        let mitigation = mitigation_for(&config);
        let template = mitigation.fetch_block_template().await.unwrap();

        assert_eq!(template.height, 1);
        assert_eq!(invalidate_counter.load(Ordering::SeqCst), 0);
        assert_eq!(header_counter.load(Ordering::SeqCst), 1);
        assert!(mitigation.deepest_invalidated().is_none());
    }

    #[tokio::test]
    async fn fetch_block_template_invalidates_chain() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        let tip_counter = Arc::new(AtomicUsize::new(0));
        let header_counter = Arc::new(AtomicUsize::new(0));
        let invalidate_counter = Arc::new(AtomicUsize::new(0));

        // Three consecutive min-diff tips, then a high-diff tip.
        mount_tip_sequence(&server, tip_counter.clone()).await;
        mount_header_sequence(
            &server,
            header_counter.clone(),
            vec![
                MIN_DIFFICULTY_BITS,
                MIN_DIFFICULTY_BITS,
                MIN_DIFFICULTY_BITS,
                0x1a01f56e,
            ],
        )
        .await;
        mount_invalidate_counter(&server, invalidate_counter.clone()).await;
        mount_template(&server).await;

        let mitigation = mitigation_for(&config);
        let template = mitigation.fetch_block_template().await.unwrap();

        assert_eq!(template.height, 1);
        assert_eq!(invalidate_counter.load(Ordering::SeqCst), 3);
        assert_eq!(header_counter.load(Ordering::SeqCst), 4);
        // The deepest hash is the 3rd tip (index 2) -- the last one invalidated.
        let deepest = mitigation.deepest_invalidated().unwrap();
        let mut expected_bytes = [0u8; 32];
        expected_bytes[24..32].copy_from_slice(&2u64.to_be_bytes());
        assert_eq!(deepest, BlockHash::from_byte_array(expected_bytes));
    }

    #[tokio::test]
    async fn fetch_block_template_respects_max_depth() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        let tip_counter = Arc::new(AtomicUsize::new(0));
        let header_counter = Arc::new(AtomicUsize::new(0));
        let invalidate_counter = Arc::new(AtomicUsize::new(0));

        mount_tip_sequence(&server, tip_counter.clone()).await;
        mount_header_sequence(&server, header_counter.clone(), vec![MIN_DIFFICULTY_BITS]).await;
        mount_invalidate_counter(&server, invalidate_counter.clone()).await;
        mount_template(&server).await;

        let mitigation = mitigation_for(&config);
        let template = mitigation.fetch_block_template().await.unwrap();

        assert_eq!(template.height, 1);
        assert_eq!(
            invalidate_counter.load(Ordering::SeqCst),
            MAX_INVALIDATIONS_PER_TEMPLATE
        );
        assert!(mitigation.deepest_invalidated().is_some());
    }

    #[tokio::test]
    async fn reconsider_task_clears_hash() {
        let (server, config) = setup_mock_bitcoin_rpc().await;
        mount_reconsider(&server).await;

        let mitigation = Arc::new(mitigation_for(&config));
        let test_hash: BlockHash =
            "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"
                .parse()
                .unwrap();
        *mitigation.deepest_invalidated.lock().unwrap() = Some(test_hash);

        // Use a very short interval for testing.
        let mitigation_clone = Arc::clone(&mitigation);
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            // Tick once immediately (tokio interval fires immediately on first tick),
            // then tick again to trigger the reconsider.
            interval.tick().await;
            interval.tick().await;
            let hash = mitigation_clone.deepest_invalidated.lock().unwrap().take();
            if let Some(block_hash) = hash {
                let _ = mitigation_clone.bitcoind.reconsiderblock(&block_hash).await;
            }
        });

        handle.await.unwrap();
        assert!(mitigation.deepest_invalidated().is_none());
    }
}
