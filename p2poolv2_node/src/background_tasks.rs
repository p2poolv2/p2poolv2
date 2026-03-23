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

use crate::signal::ShutdownReason;
use p2poolv2_lib::store::Store;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, trace};

/// Seconds in one hour.
pub const SECONDS_PER_HOUR: u64 = 3600;

/// Seconds in one day.
pub const SECONDS_PER_DAY: u64 = 86400;

/// Spawn a background task that periodically prunes old PPLNS shares.
///
/// Sends ShutdownReason::Error via exit_sender if pruning fails,
/// unless shutdown was already initiated by another component.
pub fn start_background_tasks(
    store: Arc<Store>,
    frequency: Duration,
    pplns_ttl: Duration,
    exit_sender: watch::Sender<ShutdownReason>,
    exit_receiver: watch::Receiver<ShutdownReason>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(frequency);
        loop {
            interval.tick().await;
            trace!("Running background cleanup tasks");
            let store_clone = Arc::clone(&store);
            let prune_result =
                tokio::task::spawn_blocking(move || store_clone.prune_shares(pplns_ttl)).await;
            let cleanup_failed = match prune_result {
                Ok(Ok(())) => false,
                Ok(Err(cleanup_error)) => {
                    error!("Background cleanup failed: {cleanup_error}");
                    true
                }
                Err(join_error) => {
                    error!("Background cleanup panicked: {join_error}");
                    true
                }
            };
            if cleanup_failed {
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
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_start_background_tasks_prunes_old_shares() {
        let temp_dir = tempdir().unwrap();
        let store =
            Arc::new(Store::new(temp_dir.path().to_str().unwrap().to_string(), false).unwrap());

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
            store.clone(),
            Duration::from_millis(100),
            Duration::from_secs(1800),
            exit_sender.clone(),
            exit_sender.subscribe(),
        );

        // Wait for at least one cleanup cycle
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify share was deleted (it's 1 hour old, TTL is 30 minutes)
        let remaining_shares = store.get_pplns_shares_filtered(None, None, None);
        assert_eq!(remaining_shares.len(), 0);

        // No shutdown should have been sent
        assert!(!test_receiver.has_changed().unwrap());

        handle.abort();
    }
}
