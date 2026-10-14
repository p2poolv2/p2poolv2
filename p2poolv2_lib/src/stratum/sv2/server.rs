// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local Stratum V2 listener.
//!
//! Each accepted connection speaks unencrypted SV2 frames. Job Declaration
//! and Mining are separate connections that share one [`super::JobRegistry`].

use super::session::{JobRegistry, PoolTransactionCache, Sv2Connection};
use crate::shares::merge_mining::MergeMiningCommitment;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info};

/// Bind the Stratum V2 listener to `hostname:port`.
///
/// The address is resolved the way the SV1 listener resolves its own, so a
/// host name such as `localhost` works as well as an IP literal. An error
/// here means the node has no SV2 socket, and the caller should stop.
pub async fn bind(hostname: &str, port: u16) -> Result<TcpListener, std::io::Error> {
    let listener = TcpListener::bind((hostname, port)).await?;
    info!("Stratum V2 listening on {}", listener.local_addr()?);
    Ok(listener)
}

/// Serve `listener` until `shutdown` changes.
///
/// `merge_mining` is `Some` for Bitcoin Cash, where every allocated job token
/// carries the AuxPoW commitment output. Bitcoin passes `None`. A failed
/// accept is logged and the listener keeps serving, as the SV1 server does.
pub async fn serve<ShutdownSignal>(
    listener: TcpListener,
    pool_transactions: PoolTransactionCache,
    merge_mining: Option<MergeMiningCommitment>,
    mut shutdown: watch::Receiver<ShutdownSignal>,
) {
    let registry = Arc::new(Mutex::new(JobRegistry::new(
        pool_transactions,
        merge_mining,
    )));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        tokio::spawn(handle_connection(stream, Arc::clone(&registry)));
                    }
                    Err(accept_error) => error!("Stratum V2 accept failed: {accept_error}"),
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}

async fn handle_connection(mut stream: tokio::net::TcpStream, registry: Arc<Mutex<JobRegistry>>) {
    let mut connection = Sv2Connection::new(registry);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stratum::sv2::session::encode_message;
    use common_messages_sv2::{
        MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol,
        SetupConnection,
    };
    use framing_sv2::framing::SerializedFrame;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn bind_resolves_a_host_name() {
        let listener = bind("localhost", 0).await.unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    #[tokio::test]
    async fn bind_reports_an_unresolvable_host() {
        assert!(bind("no-such-host.invalid", 0).await.is_err());
    }

    #[tokio::test]
    async fn served_listener_answers_setup_connection() {
        let listener = bind("localhost", 0).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_sender, shutdown_receiver) = watch::channel(());
        let server = tokio::spawn(serve(
            listener,
            PoolTransactionCache::new(),
            Some(MergeMiningCommitment::reserved()),
            shutdown_receiver,
        ));

        let mut stream = TcpStream::connect(address).await.unwrap();
        let setup = encode_message(
            SetupConnection {
                protocol: Protocol::JobDeclarationProtocol,
                min_version: 2,
                max_version: 2,
                flags: 0,
                endpoint_host: "localhost".try_into().unwrap(),
                endpoint_port: address.port(),
                vendor: "p2poolv2".try_into().unwrap(),
                hardware_version: "test".try_into().unwrap(),
                firmware: "test".try_into().unwrap(),
                device_id: "".try_into().unwrap(),
            },
            MESSAGE_TYPE_SETUP_CONNECTION,
        )
        .unwrap();
        stream.write_all(&setup).await.unwrap();
        let mut response = vec![0u8; 64];
        let read = stream.read(&mut response).await.unwrap();
        response.truncate(read);
        let frame = SerializedFrame::<Vec<u8>>::from_bytes(response).unwrap();
        assert_eq!(
            frame.header().msg_type(),
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS
        );

        shutdown_sender.send(()).unwrap();
        server.await.unwrap();
    }
}
