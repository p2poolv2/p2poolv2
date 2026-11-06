// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The confirmed share chain tip for `blockchain.headers.subscribe`.
//!
//! Each Electrum server instance runs one tip watcher. When the node's
//! confirmed tip changes (a new share or a reorg), the watcher reads the
//! tip from the store and publishes it on a `watch` channel that every
//! connection listens to.
//!
//! Connections take the tip only from this channel, for both the answer
//! to a subscribe and every later notification. Each new value on the
//! channel was read later than the one before, so a wallet is never sent
//! a tip that is older than one it already has. If a connection read the
//! store itself, its subscribe answer could be newer than the channel, and
//! the next notification would then go back to an older tip.

use crate::error::ElectrumServerError;
use bitcoin::consensus::encode::serialize_hex;
use p2poolv2_lib::monitoring_events::MonitoringEventReceiver;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::writer::StoreError;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// The latest published tip, `None` until the node is first current.
pub(crate) type TipSender = watch::Sender<Option<Arc<Tip>>>;

/// A connection's view of the published tip.
pub(crate) type TipReceiver = watch::Receiver<Option<Arc<Tip>>>;

/// A confirmed tip, with its header encoded once for every client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tip {
    pub(crate) height: u32,
    /// Hex of the consensus-encoded `ShareHeader`, as
    /// `blockchain.block.header` returns it.
    pub(crate) header_hex: String,
}

impl Tip {
    /// The Electrum header object, `{"height", "hex"}`.
    pub(crate) fn to_json(&self) -> Value {
        json!({ "height": self.height, "hex": self.header_hex })
    }
}

/// Read the confirmed tip height and the header at that height.
pub(crate) fn read_tip(chain_store_handle: &ChainStoreHandle) -> Result<Tip, StoreError> {
    let height = chain_store_handle
        .get_tip_height()?
        .ok_or_else(|| StoreError::NotFound("no confirmed share chain".into()))?;
    let header = chain_store_handle
        .get_confirmed_at_height(height)
        .and_then(|blockhash| chain_store_handle.get_share_header(&blockhash))?;
    Ok(Tip {
        height,
        header_hex: serialize_hex(&header),
    })
}

/// Publish the tip on `tip_sender` until `shutdown` is cancelled or the
/// monitoring channel closes.
///
/// Publishes after every wake-up on `event_receiver`; the caller publishes
/// the first tip with `publish_tip` before starting the watcher, so
/// subscribe `event_receiver` before that first read to miss no change.
/// A wake-up first drains every event already queued, so a sync burst of
/// thousands of confirmed shares costs one tip read, and a `Lagged`
/// receiver just reads again. Any event wakes the watcher; peer events are
/// rare, and a read that finds the same tip publishes nothing.
pub(crate) async fn run_tip_watcher(
    chain_store_handle: ChainStoreHandle,
    mut event_receiver: MonitoringEventReceiver,
    tip_sender: TipSender,
    shutdown: CancellationToken,
) {
    let mut running = true;
    while running {
        running = tokio::select! {
            _ = shutdown.cancelled() => false,
            received = event_receiver.recv() => match received {
                Ok(_) | Err(RecvError::Lagged(_)) => {
                    drain_queued_events(&mut event_receiver);
                    // A failed read is retried on the next event.
                    if let Err(error) = publish_tip(&chain_store_handle, &tip_sender).await {
                        warn!("{error}");
                    }
                    true
                }
                Err(RecvError::Closed) => {
                    debug!("Monitoring event channel closed, Electrum tip watcher stopping");
                    false
                }
            },
        };
    }
}

/// Discard the events already queued. A lagged queue is skipped over the
/// same way; only the tip read afterwards matters.
fn drain_queued_events(event_receiver: &mut MonitoringEventReceiver) {
    while !matches!(
        event_receiver.try_recv(),
        Err(TryRecvError::Empty | TryRecvError::Closed)
    ) {}
}

/// Read the tip on a blocking thread and publish it if the node is current
/// and the tip changed. While the node is not current nothing is
/// published, so clients get no notifications until it is current again.
/// A failed read publishes nothing and returns the error.
pub(crate) async fn publish_tip(
    chain_store_handle: &ChainStoreHandle,
    tip_sender: &TipSender,
) -> Result<(), ElectrumServerError> {
    let chain_store_handle = chain_store_handle.clone();
    let read = tokio::task::spawn_blocking(move || {
        if chain_store_handle.is_current() {
            read_tip(&chain_store_handle).map(Some)
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(ElectrumServerError::TipReadTask)?
    .map_err(ElectrumServerError::TipRead)?;
    if let Some(tip) = read {
        tip_sender.send_if_modified(|published| {
            let changed = published.as_deref() != Some(&tip);
            if changed {
                *published = Some(Arc::new(tip));
            }
            changed
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{build_current_test_chain, wake_event};
    use bitcoin::consensus::encode::deserialize_hex;
    use p2poolv2_lib::monitoring_events::{MonitoringEvent, create_monitoring_event_channel};
    use p2poolv2_lib::shares::share_block::ShareHeader;
    use p2poolv2_lib::test_utils::{
        TestShareBlockBuilder, build_confirmed_test_chain, confirm_test_block,
        setup_test_chain_store_handle, test_funding_transaction,
    };
    use std::time::Duration;
    use tokio::sync::broadcast;
    use tokio::time::timeout;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn read_tip_returns_height_and_encoded_tip_header() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 3).await;

        let tip = read_tip(&chain_store_handle).unwrap();

        assert_eq!(tip.height, 3);
        let decoded: ShareHeader = deserialize_hex(&tip.header_hex).unwrap();
        assert_eq!(decoded, blocks[3].header);
        assert_eq!(tip.to_json(), json!({ "height": 3, "hex": tip.header_hex }));
    }

    #[tokio::test]
    async fn drain_discards_every_queued_event() {
        let event_sender = create_monitoring_event_channel();
        let mut event_receiver = event_sender.subscribe();
        event_sender.send(wake_event()).unwrap();
        event_sender.send(wake_event()).unwrap();
        event_sender.send(wake_event()).unwrap();

        drain_queued_events(&mut event_receiver);

        assert!(matches!(
            event_receiver.try_recv(),
            Err(TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn publish_tip_publishes_tip_of_current_chain() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let (tip_sender, mut tip_receiver) = watch::channel(None);

        publish_tip(&chain_store_handle, &tip_sender).await.unwrap();

        assert!(tip_receiver.has_changed().unwrap());
        let published = tip_receiver.borrow_and_update().clone().unwrap();
        assert_eq!(*published, read_tip(&chain_store_handle).unwrap());
        assert_eq!(published.height, 2);
    }

    #[tokio::test]
    async fn publish_tip_on_stale_chain_publishes_nothing() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 2).await;
        let (tip_sender, tip_receiver) = watch::channel(None);

        publish_tip(&chain_store_handle, &tip_sender).await.unwrap();

        assert!(!tip_receiver.has_changed().unwrap());
        assert!(tip_receiver.borrow().is_none());
    }

    #[tokio::test]
    async fn event_after_new_confirmed_block_publishes_new_tip() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let blocks = build_current_test_chain(&chain_store_handle, 2).await;
        let event_sender = create_monitoring_event_channel();
        let event_receiver = event_sender.subscribe();
        let (tip_sender, mut tip_receiver) = watch::channel(None);
        publish_tip(&chain_store_handle, &tip_sender).await.unwrap();
        tip_receiver.borrow_and_update();
        let shutdown = CancellationToken::new();
        let _watcher = tokio::spawn(run_tip_watcher(
            chain_store_handle.clone(),
            event_receiver,
            tip_sender,
            shutdown.clone(),
        ));

        let next_block = TestShareBlockBuilder::new()
            .prev_share_blockhash(blocks[2].block_hash().to_string())
            .time(blocks[2].header.time + 1)
            .add_transaction(test_funding_transaction(3))
            .build();
        confirm_test_block(&chain_store_handle, &next_block).await;
        event_sender.send(wake_event()).unwrap();
        timeout(TEST_TIMEOUT, tip_receiver.changed())
            .await
            .unwrap()
            .unwrap();

        let published = tip_receiver.borrow_and_update().clone().unwrap();
        assert_eq!(published.height, 3);
        let decoded: ShareHeader = deserialize_hex(&published.header_hex).unwrap();
        assert_eq!(decoded, next_block.header);
        shutdown.cancel();
    }

    /// Events that find the tip unchanged publish nothing, so connections
    /// are not woken for a tip they already have. The test keeps a sender
    /// clone, so `has_changed` reports on the channel, not on its closing.
    #[tokio::test]
    async fn events_with_unchanged_tip_publish_nothing_more() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 3).await;
        let (tip_sender, mut tip_receiver) = watch::channel(None);
        publish_tip(&chain_store_handle, &tip_sender).await.unwrap();
        assert_eq!(tip_receiver.borrow_and_update().as_ref().unwrap().height, 3);
        let event_sender = create_monitoring_event_channel();
        let event_receiver = event_sender.subscribe();
        event_sender.send(wake_event()).unwrap();
        event_sender.send(wake_event()).unwrap();
        let watcher = tokio::spawn(run_tip_watcher(
            chain_store_handle,
            event_receiver,
            tip_sender.clone(),
            CancellationToken::new(),
        ));

        drop(event_sender);
        timeout(TEST_TIMEOUT, watcher).await.unwrap().unwrap();

        assert!(!tip_receiver.has_changed().unwrap());
    }

    #[tokio::test]
    async fn stale_chain_publishes_nothing() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_confirmed_test_chain(&chain_store_handle, 2).await;
        let event_sender = create_monitoring_event_channel();
        let event_receiver = event_sender.subscribe();
        event_sender.send(wake_event()).unwrap();
        let (tip_sender, tip_receiver) = watch::channel(None);
        let watcher = tokio::spawn(run_tip_watcher(
            chain_store_handle,
            event_receiver,
            tip_sender,
            CancellationToken::new(),
        ));

        drop(event_sender);
        timeout(TEST_TIMEOUT, watcher).await.unwrap().unwrap();

        assert!(tip_receiver.borrow().is_none());
    }

    /// A one-slot channel overflows on the second send. Both sends happen
    /// before the spawned watcher first runs (the test runtime is single
    /// threaded), so its first receive is `Lagged`, and only reading again
    /// on `Lagged` can publish the tip.
    #[tokio::test]
    async fn lagged_receiver_reads_tip_again() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        build_current_test_chain(&chain_store_handle, 2).await;
        let (event_sender, event_receiver) = broadcast::channel::<MonitoringEvent>(1);
        let (tip_sender, mut tip_receiver) = watch::channel(None);
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(run_tip_watcher(
            chain_store_handle,
            event_receiver,
            tip_sender,
            shutdown.clone(),
        ));

        event_sender.send(wake_event()).unwrap();
        event_sender.send(wake_event()).unwrap();
        timeout(TEST_TIMEOUT, tip_receiver.changed())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(tip_receiver.borrow_and_update().as_ref().unwrap().height, 2);
        shutdown.cancel();
        timeout(TEST_TIMEOUT, watcher).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancelling_shutdown_ends_watcher() {
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let event_sender = create_monitoring_event_channel();
        let event_receiver = event_sender.subscribe();
        let (tip_sender, _tip_receiver) = watch::channel(None);
        let shutdown = CancellationToken::new();
        let watcher = tokio::spawn(run_tip_watcher(
            chain_store_handle,
            event_receiver,
            tip_sender,
            shutdown.clone(),
        ));

        shutdown.cancel();

        timeout(TEST_TIMEOUT, watcher).await.unwrap().unwrap();
    }
}
