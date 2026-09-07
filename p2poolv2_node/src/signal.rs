// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(unix)]
use tokio::signal::unix::{self, SignalKind};

use tokio::{sync::watch, task::JoinHandle};
use tracing::info;

/// Reason for shutdown - used to determine exit code
/// Correct exit code will help service runners
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    /// No shutdown requested yet
    None,
    /// Clean shutdown from user signal (ctrl-c, SIGTERM, SIGHUP)
    Signal,
    /// Shutdown due to component error
    Error,
}

#[cfg(unix)]
pub fn setup_signal_handler(exit_sender: watch::Sender<ShutdownReason>) -> JoinHandle<()> {
    let mut exit_receiver = exit_sender.subscribe();
    // future: improve this by implementing sigterm. Maybe usr1 and 2 for things like committing to disk
    tokio::spawn(async move {
        let mut hangup =
            unix::signal(SignalKind::hangup()).expect("Failed to listen to hangup signal");
        let mut terminate =
            unix::signal(SignalKind::terminate()).expect("Failed to listen to terminate signal");

        let sig = tokio::select! {
            _ = exit_receiver.changed() => None,
            _ = tokio::signal::ctrl_c() => Some(SignalKind::interrupt()),
            _ = hangup.recv() => Some(SignalKind::hangup()),
            _ = terminate.recv() => Some(SignalKind::terminate()),
        };

        if let Some(sig) = sig {
            info!("Received signal {sig:?}. Stopping...");
            let _ = exit_sender.send(ShutdownReason::Signal);
        };
    })
}

#[cfg(not(unix))]
pub fn setup_signal_handler(exit_sender: watch::Sender<ShutdownReason>) -> JoinHandle<()> {
    let mut exit_receiver = exit_sender.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            _ = exit_receiver.changed() => {},
            _ = tokio::signal::ctrl_c() => {
                info!("Received ctrl-c signal. Stopping...");
                let _ = exit_sender.send(ShutdownReason::Signal);
            },
        };
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_signal_handler_exits_on_shutdown_signal() {
        let (exit_sender, _) = watch::channel(ShutdownReason::None);
        let handle = setup_signal_handler(exit_sender.clone());

        // Send shutdown signal via the watch channel
        exit_sender.send(ShutdownReason::Signal).unwrap();

        // Handler should exit promptly
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), handle).await;

        assert!(
            result.is_ok(),
            "Handler should exit when shutdown signal is sent"
        );
    }
}
