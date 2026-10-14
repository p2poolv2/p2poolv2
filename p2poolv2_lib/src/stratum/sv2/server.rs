// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local Stratum V2 listener.
//!
//! Each accepted connection speaks unencrypted SV2 frames. Job Declaration
//! and Mining are separate connections that share one [`super::JobRegistry`].

use super::session::{JobRegistry, PoolTransactionCache, Sv2Connection};
use crate::shares::merge_mining::MergeMiningCommitment;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;

/// Listen on `address` until `shutdown` changes.
///
/// `merge_mining` is `Some` for Bitcoin Cash, where every allocated job token
/// carries the AuxPoW commitment output. Bitcoin passes `None`.
pub async fn serve(
    address: SocketAddr,
    pool_transactions: PoolTransactionCache,
    merge_mining: Option<MergeMiningCommitment>,
    mut shutdown: watch::Receiver<()>,
) -> Result<(), std::io::Error> {
    let listener = TcpListener::bind(address).await?;
    let registry = Arc::new(Mutex::new(JobRegistry::new(
        pool_transactions,
        merge_mining,
    )));
    info!("Stratum V2 listening on {address}");
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, _peer) = accepted?;
                let connection_registry = Arc::clone(&registry);
                tokio::spawn(async move {
                    let mut connection = Sv2Connection::new(connection_registry);
                    let mut buffer = vec![0u8; 4096];
                    loop {
                        let read = match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => return,
                            Ok(count) => count,
                        };
                        let responses = match connection.accept(&buffer[..read]) {
                            Ok(responses) => responses,
                            Err(_) => return,
                        };
                        for response in responses {
                            if stream.write_all(&response).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
            _ = shutdown.changed() => return Ok(()),
        }
    }
}
