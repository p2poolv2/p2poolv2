// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::signal::ShutdownReason;
use p2poolv2_lib::config::PoolMode;
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::Store;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{error, trace};

/// Seconds in one hour.
pub const SECONDS_PER_HOUR: u64 = 3600;

/// Seconds in one day.
pub const SECONDS_PER_DAY: u64 = 86400;

/// How often the background tasks run. Fixed in code: the PPLNS share TTL
/// is days long and block body pruning only needs to keep pace with the
/// chain, so neither is worth tuning.
pub const BACKGROUND_TASK_INTERVAL: Duration = Duration::from_secs(6 * SECONDS_PER_HOUR);

/// Spawn the background cleanup task for the pool mode.
///
/// Hydrapool mode stores PPLNS shares and prunes them past `pplns_ttl`.
/// P2Poolv2 mode stores the share chain and prunes block bodies below the
/// prune target.
pub fn start_background_tasks(
    mode: PoolMode,
    store: Arc<Store>,
    chain_store_handle: ChainStoreHandle,
    pplns_ttl: Duration,
    exit_sender: watch::Sender<ShutdownReason>,
    exit_receiver: watch::Receiver<ShutdownReason>,
) -> tokio::task::JoinHandle<()> {
    match mode {
        PoolMode::Hydrapool => {
            start_pplns_share_pruning(store, pplns_ttl, exit_sender, exit_receiver)
        }
        PoolMode::P2poolv2 => {
            start_block_body_pruning(chain_store_handle, exit_sender, exit_receiver)
        }
    }
}

/// Spawn a task that prunes PPLNS shares older than `pplns_ttl`.
///
/// Runs every `BACKGROUND_TASK_INTERVAL`, the first time immediately. A run
/// that overruns the interval delays the next tick rather than bursting. Sends
/// ShutdownReason::Error via exit_sender if pruning fails, unless shutdown
/// was already initiated by another component.
fn start_pplns_share_pruning(
    store: Arc<Store>,
    pplns_ttl: Duration,
    exit_sender: watch::Sender<ShutdownReason>,
    exit_receiver: watch::Receiver<ShutdownReason>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(BACKGROUND_TASK_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            trace!("Pruning old PPLNS shares");
            let store_clone = Arc::clone(&store);
            let prune_result =
                tokio::task::spawn_blocking(move || store_clone.prune_shares(pplns_ttl)).await;
            let prune_failed = match prune_result {
                Ok(Ok(())) => false,
                Ok(Err(prune_error)) => {
                    error!("PPLNS share pruning failed: {prune_error}");
                    true
                }
                Err(join_error) => {
                    error!("PPLNS share pruning panicked: {join_error}");
                    true
                }
            };
            if prune_failed {
                if *exit_receiver.borrow() == ShutdownReason::None {
                    let _ = exit_sender.send(ShutdownReason::Error);
                }
                return;
            }
        }
    })
}

/// Spawn a task that prunes block bodies below the prune target.
///
/// Runs every `BACKGROUND_TASK_INTERVAL`, the first time immediately. A run
/// that overruns the interval delays the next tick rather than bursting. Sends
/// ShutdownReason::Error via exit_sender if pruning fails, unless shutdown
/// was already initiated by another component.
fn start_block_body_pruning(
    chain_store_handle: ChainStoreHandle,
    exit_sender: watch::Sender<ShutdownReason>,
    exit_receiver: watch::Receiver<ShutdownReason>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(BACKGROUND_TASK_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut next_prune_start: Option<u32> = None;
        loop {
            interval.tick().await;
            trace!("Pruning block bodies");
            if let Err(prune_error) = chain_store_handle
                .prune_block_bodies_if_due(&mut next_prune_start)
                .await
            {
                error!("Block body pruning failed: {prune_error}");
                if *exit_receiver.borrow() == ShutdownReason::None {
                    let _ = exit_sender.send(ShutdownReason::Error);
                }
                return;
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2poolv2_lib::accounting::payout::simple_pplns::SimplePplnsShare;
    use p2poolv2_lib::test_utils::setup_test_chain_store_handle;

    /// Hydrapool mode prunes PPLNS shares older than the TTL.
    #[tokio::test]
    async fn test_start_background_tasks_in_hydrapool_mode_prunes_old_shares() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let store = Arc::clone(chain_store_handle.store_handle().store());
        let user_id = store.add_user("addr1".to_string()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old_share = SimplePplnsShare::new(
            user_id,
            100,
            "addr1".to_string(),
            "worker1".to_string(),
            now - 3600,
            "job".to_string(),
            "extra".to_string(),
            "nonce".to_string(),
        );
        store.add_pplns_share(old_share).unwrap();
        let (exit_sender, _exit_receiver) = watch::channel(ShutdownReason::None);
        let test_receiver = exit_sender.subscribe();

        let handle = start_background_tasks(
            PoolMode::Hydrapool,
            store.clone(),
            chain_store_handle,
            Duration::from_secs(1800),
            exit_sender.clone(),
            exit_sender.subscribe(),
        );

        // The first cleanup cycle runs immediately
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The share is 1 hour old and the TTL is 30 minutes
        let remaining_shares = store.get_pplns_shares_filtered(None, None, None);
        assert_eq!(remaining_shares.len(), 0);
        assert!(!test_receiver.has_changed().unwrap());

        handle.abort();
    }

    /// P2Poolv2 mode does not store PPLNS shares, so it does not prune them.
    #[tokio::test]
    async fn test_start_background_tasks_in_p2poolv2_mode_keeps_pplns_shares() {
        let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;
        let store = Arc::clone(chain_store_handle.store_handle().store());
        let user_id = store.add_user("addr1".to_string()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let old_share = SimplePplnsShare::new(
            user_id,
            100,
            "addr1".to_string(),
            "worker1".to_string(),
            now - 3600,
            "job".to_string(),
            "extra".to_string(),
            "nonce".to_string(),
        );
        store.add_pplns_share(old_share).unwrap();
        let (exit_sender, _exit_receiver) = watch::channel(ShutdownReason::None);
        let test_receiver = exit_sender.subscribe();

        let handle = start_background_tasks(
            PoolMode::P2poolv2,
            store.clone(),
            chain_store_handle,
            Duration::from_secs(1800),
            exit_sender.clone(),
            exit_sender.subscribe(),
        );

        // The first cleanup cycle runs immediately
        tokio::time::sleep(Duration::from_millis(200)).await;

        let remaining_shares = store.get_pplns_shares_filtered(None, None, None);
        assert_eq!(remaining_shares.len(), 1);
        assert!(!test_receiver.has_changed().unwrap());

        handle.abort();
    }
}
