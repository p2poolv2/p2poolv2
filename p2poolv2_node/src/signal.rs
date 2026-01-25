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

#[cfg(unix)]
use tokio::signal::unix::{self, SignalKind};

use tokio::{sync::watch::Sender, task::JoinHandle};
use tracing::info;

#[cfg(unix)]
pub fn setup_signal_handler(exit_sender: Sender<bool>) -> JoinHandle<()> {
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

            exit_sender
                .send(true)
                .expect("failed to set shutdown signal");
        };
    })
}

#[cfg(not(unix))]
pub fn setup_signal_handler(exit_sender: Sender<bool>) -> JoinHandle<()> {
    let mut exit_receiver = exit_sender.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            _ = exit_receiver.changed() => {},
            _ = tokio::signal::ctrl_c() => {
                info!("Received ctrl-c signal. Stopping...");
                exit_sender
                    .send(true)
                    .expect("failed to set shutdown signal");
            }
        };
    })
}
