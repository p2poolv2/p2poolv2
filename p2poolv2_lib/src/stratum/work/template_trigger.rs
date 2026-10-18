// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wake-ups for the template task besides its poll.
//!
//! The template task fetches a new block template on a ZMQ `hashblock` event
//! or when its poll interval elapses. Neither fires when this node itself
//! finds a block: the ZMQ endpoint can be unreachable (a remote node), and
//! the poll can be up to `GBT_POLL_INTERVAL` away. Until then every miner
//! keeps working on the parent of the block just found, so any further block
//! it finds is a same-height sibling that loses.
//!
//! [`merge_template_triggers`] adds a refresh channel beside the ZMQ one and
//! forwards both into the single receiver the template task already reads.

use tokio::sync::mpsc;

/// Merge the ZMQ trigger with a refresh channel the stratum servers signal
/// after submitting a found block.
///
/// Returns the refresh sender, for the stratum servers, and the merged
/// receiver, for `start_gbt`. Both channels hold one pending wake-up, so a
/// burst of requests while a template is being fetched becomes one fetch.
/// The forwarder ends when the template task drops the merged receiver, or
/// when both inputs are closed.
pub fn merge_template_triggers(
    mut zmq_trigger_rx: mpsc::Receiver<()>,
) -> (mpsc::Sender<()>, mpsc::Receiver<()>) {
    let (refresh_tx, mut refresh_rx) = mpsc::channel(1);
    let (trigger_tx, trigger_rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let mut zmq_open = true;
        let mut refresh_open = true;
        while zmq_open || refresh_open {
            let wake = tokio::select! {
                event = zmq_trigger_rx.recv(), if zmq_open => {
                    zmq_open = event.is_some();
                    event
                }
                event = refresh_rx.recv(), if refresh_open => {
                    refresh_open = event.is_some();
                    event
                }
            };
            if wake.is_some() && trigger_tx.send(()).await.is_err() {
                break;
            }
        }
    });
    (refresh_tx, trigger_rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    async fn next(trigger_rx: &mut mpsc::Receiver<()>) -> Option<()> {
        timeout(Duration::from_secs(2), trigger_rx.recv())
            .await
            .expect("a trigger arrives")
    }

    #[tokio::test]
    async fn a_refresh_request_wakes_the_template_task() {
        let (_zmq_tx, zmq_rx) = mpsc::channel(1);
        let (refresh_tx, mut trigger_rx) = merge_template_triggers(zmq_rx);
        refresh_tx.try_send(()).unwrap();
        assert_eq!(next(&mut trigger_rx).await, Some(()));
    }

    #[tokio::test]
    async fn a_zmq_event_still_wakes_the_template_task() {
        let (zmq_tx, zmq_rx) = mpsc::channel(1);
        let (_refresh_tx, mut trigger_rx) = merge_template_triggers(zmq_rx);
        zmq_tx.send(()).await.unwrap();
        assert_eq!(next(&mut trigger_rx).await, Some(()));
    }

    #[tokio::test]
    async fn refreshes_keep_working_after_zmq_closes() {
        let (zmq_tx, zmq_rx) = mpsc::channel(1);
        let (refresh_tx, mut trigger_rx) = merge_template_triggers(zmq_rx);
        drop(zmq_tx);
        refresh_tx.try_send(()).unwrap();
        assert_eq!(next(&mut trigger_rx).await, Some(()));
    }

    #[tokio::test]
    async fn a_burst_of_requests_is_coalesced() {
        let (_zmq_tx, zmq_rx) = mpsc::channel(1);
        let (refresh_tx, mut trigger_rx) = merge_template_triggers(zmq_rx);
        for _ in 0..10 {
            let _ = refresh_tx.try_send(());
        }
        assert_eq!(next(&mut trigger_rx).await, Some(()));
        // At most one request is in the refresh channel and one in the
        // forwarder, so the burst yields at most two wake-ups, not ten.
        let mut extra = 0;
        while timeout(Duration::from_millis(200), trigger_rx.recv())
            .await
            .is_ok()
        {
            extra += 1;
        }
        assert!(extra <= 1, "{extra} extra wake-ups");
    }

    #[tokio::test]
    async fn the_merged_receiver_closes_when_both_inputs_close() {
        let (zmq_tx, zmq_rx) = mpsc::channel(1);
        let (refresh_tx, mut trigger_rx) = merge_template_triggers(zmq_rx);
        drop(zmq_tx);
        drop(refresh_tx);
        assert_eq!(next(&mut trigger_rx).await, None);
    }
}
