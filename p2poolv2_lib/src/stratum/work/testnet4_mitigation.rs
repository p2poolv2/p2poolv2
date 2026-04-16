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

//! Testnet4 min-difficulty block filtering.
//!
//! During the testnet4 timing attack, attackers exploit the 20-minute rule to
//! cheaply mine blocks at the network's minimum difficulty (compact bits
//! `0x1d00ffff`). This module's entry point invalidates such blocks at the tip
//! before serving a block template to local miners, so we build on top of a
//! non-attack ancestor.
//!
//! Invalidations are fire-and-forget: we drop the block hashes immediately and
//! never call `reconsiderblock`. If bitcoind subsequently reorgs back to a
//! min-diff tip, the next call to this entry point will invalidate it again.

use crate::stratum::work::block_template::BlockTemplate;
use crate::stratum::work::gbt::fetch_template_directly;
use bitcoindrpc::BitcoindRpcClient;
use tracing::{info, warn};

/// Compact `bits` value for testnet's pow_limit. Any block at the tip with
/// this value is a 20-minute-rule min-difficulty block on testnet4.
const MIN_DIFFICULTY_BITS: u32 = 0x1d00ffff;

/// Cap on the number of consecutive ancestor blocks we will invalidate in a
/// single template fetch. Bounds RPC traffic and prevents runaway invalidation
/// if the entire visible tail of the chain is min-difficulty.
const MAX_INVALIDATIONS_PER_TEMPLATE: usize = 100;

/// Walk back from the tip invalidating min-difficulty blocks, then fetch a
/// fresh block template.
///
/// Stops after the first non-min-difficulty tip is reached, or after
/// `MAX_INVALIDATIONS_PER_TEMPLATE` invalidations, whichever comes first.
/// Always proceeds to fetch and return a template from bitcoind, even if the
/// invalidation cap was hit (best-effort mitigation).
pub async fn fetch_block_template_with_filtering(
    bitcoind: &BitcoindRpcClient,
    network: bitcoin::Network,
) -> Result<BlockTemplate, Box<dyn std::error::Error + Send + Sync>> {
    let mut invalidated = 0usize;
    while invalidated < MAX_INVALIDATIONS_PER_TEMPLATE {
        let tip = bitcoind.getbestblockhash().await?;
        let bits = bitcoind.getblockheader_bits(&tip).await?;
        if bits != MIN_DIFFICULTY_BITS {
            break;
        }
        bitcoind.invalidateblock(&tip).await?;
        info!("Invalidated min-difficulty tip {tip} (bits={bits:#x})");
        invalidated += 1;
    }
    if invalidated == MAX_INVALIDATIONS_PER_TEMPLATE {
        warn!(
            "Reached invalidation cap of {} for a single template fetch; \
             proceeding with current tip",
            MAX_INVALIDATIONS_PER_TEMPLATE
        );
    }
    fetch_template_directly(bitcoind, network).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::BlockHash;
    use bitcoin::hashes::Hash;
    use bitcoindrpc::test_utils::{mock_method, setup_mock_bitcoin_rpc};
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    /// Test responder that hands back a sequence of canned `bits` values
    /// (one per `getblockheader` call), tracking how many times it was hit.
    /// Each invocation also rotates the tip hash by hashing the call index so
    /// `getbestblockhash` returns a distinct hash per invalidation.
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

    fn client_for(config: &bitcoindrpc::BitcoinRpcConfig) -> BitcoindRpcClient {
        BitcoindRpcClient::new(&config.url, &config.username, &config.password).unwrap()
    }

    #[tokio::test]
    async fn fetch_block_template_with_filtering_no_invalidation() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        let tip_counter = Arc::new(AtomicUsize::new(0));
        let header_counter = Arc::new(AtomicUsize::new(0));
        let invalidate_counter = Arc::new(AtomicUsize::new(0));

        // First and only header lookup returns a non-min-diff bits value.
        mount_tip_sequence(&server, tip_counter.clone()).await;
        mount_header_sequence(&server, header_counter.clone(), vec![0x1a01f56e]).await;
        mount_invalidate_counter(&server, invalidate_counter.clone()).await;
        mount_template(&server).await;

        let client = client_for(&config);
        let template = fetch_block_template_with_filtering(&client, bitcoin::Network::Bitcoin)
            .await
            .unwrap();

        assert_eq!(template.height, 1);
        assert_eq!(invalidate_counter.load(Ordering::SeqCst), 0);
        assert_eq!(header_counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fetch_block_template_with_filtering_invalidates_chain() {
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

        let client = client_for(&config);
        let template = fetch_block_template_with_filtering(&client, bitcoin::Network::Bitcoin)
            .await
            .unwrap();

        assert_eq!(template.height, 1);
        assert_eq!(invalidate_counter.load(Ordering::SeqCst), 3);
        assert_eq!(header_counter.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn fetch_block_template_with_filtering_respects_max_depth() {
        let (server, config) = setup_mock_bitcoin_rpc().await;

        let tip_counter = Arc::new(AtomicUsize::new(0));
        let header_counter = Arc::new(AtomicUsize::new(0));
        let invalidate_counter = Arc::new(AtomicUsize::new(0));

        // Every header lookup returns min-diff bits forever.
        mount_tip_sequence(&server, tip_counter.clone()).await;
        mount_header_sequence(&server, header_counter.clone(), vec![MIN_DIFFICULTY_BITS]).await;
        mount_invalidate_counter(&server, invalidate_counter.clone()).await;
        mount_template(&server).await;

        let client = client_for(&config);
        let template = fetch_block_template_with_filtering(&client, bitcoin::Network::Bitcoin)
            .await
            .unwrap();

        assert_eq!(template.height, 1);
        assert_eq!(
            invalidate_counter.load(Ordering::SeqCst),
            MAX_INVALIDATIONS_PER_TEMPLATE
        );
        assert_eq!(
            header_counter.load(Ordering::SeqCst),
            MAX_INVALIDATIONS_PER_TEMPLATE
        );
    }
}
