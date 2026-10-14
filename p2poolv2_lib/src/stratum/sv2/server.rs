// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local Stratum V2 listener.
//!
//! Each accepted connection speaks unencrypted SV2 frames. Job Declaration
//! and Mining are separate connections that share one [`super::JobRegistry`].
//! A Mining connection may also open standard and extended channels, which
//! get a job for every template the SV1 server sees (see `super::mining`).

use super::mining::{MiningChannels, is_mining_channel_message};
use super::session::{JobRegistry, PoolTransactionCache, Sv2Connection};
use crate::shares::merge_mining::MergeMiningCommitment;
use crate::stratum::server::StratumContext;
use crate::stratum::work::prepared_notify::PreparedNotifyParams;
use std::future;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{error, info};

/// Watch channel the SV1 notifier publishes prepared templates on.
pub(crate) type TemplateReceiver = watch::Receiver<Option<Arc<PreparedNotifyParams>>>;

/// What a listener needs to serve Mining Protocol channels: the SV1 stratum
/// context, the version-rolling mask, and the template watch.
pub(crate) struct Sv2Mining {
    pub ctx: StratumContext,
    pub version_mask: i32,
    pub template_rx: TemplateReceiver,
}

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

/// Serve `listener` until `shutdown` changes or its sender is dropped.
///
/// `merge_mining` is `Some` for Bitcoin Cash, where every allocated job token
/// carries the AuxPoW commitment output. Bitcoin passes `None`. `mining` is
/// `None` when the listener only speaks Job Declaration. A failed accept is
/// logged and the listener keeps serving, as the SV1 server does.
pub(crate) async fn serve<ShutdownSignal>(
    listener: TcpListener,
    pool_transactions: PoolTransactionCache,
    merge_mining: Option<MergeMiningCommitment>,
    mining: Option<Sv2Mining>,
    mut shutdown: watch::Receiver<ShutdownSignal>,
) where
    ShutdownSignal: Send + Sync + 'static,
{
    let registry = Arc::new(Mutex::new(JobRegistry::new(
        pool_transactions,
        merge_mining,
    )));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        let connection_mining = mining.as_ref().map(|services| Sv2Mining {
                            ctx: services.ctx.clone(),
                            version_mask: services.version_mask,
                            template_rx: services.template_rx.clone(),
                        });
                        tokio::spawn(handle_connection(
                            stream,
                            Arc::clone(&registry),
                            connection_mining,
                            shutdown.clone(),
                        ));
                    }
                    Err(accept_error) => error!("Stratum V2 accept failed: {accept_error}"),
                }
            }
            _ = shutdown.changed() => return,
        }
    }
}

async fn handle_connection<ShutdownSignal>(
    stream: TcpStream,
    registry: Arc<Mutex<JobRegistry>>,
    mining: Option<Sv2Mining>,
    mut shutdown: watch::Receiver<ShutdownSignal>,
) {
    let mut connection = Sv2Connection::new(registry);
    let (mut template_rx, mut channels) = match mining {
        Some(services) => (
            Some(services.template_rx),
            Some(MiningChannels::new(services.ctx, services.version_mask)),
        ),
        None => (None, None),
    };
    let (mut reader, mut writer) = stream.into_split();
    let mut buffer = vec![0u8; 4096];
    loop {
        let frames = tokio::select! {
            read = reader.read(&mut buffer) => {
                let count = match read {
                    Ok(0) | Err(_) => return,
                    Ok(count) => count,
                };
                match handle_bytes(
                    &mut connection,
                    channels.as_mut(),
                    template_rx.as_mut(),
                    &buffer[..count],
                )
                .await
                {
                    Ok(frames) => frames,
                    Err(_) => return,
                }
            }
            prepared = next_template(template_rx.as_mut()) => {
                match (prepared, channels.as_mut()) {
                    (Some(prepared), Some(channels)) => channels.on_template(&prepared),
                    _ => Vec::new(),
                }
            }
            _ = shutdown.changed() => return,
        };
        for frame in frames {
            if writer.write_all(&frame).await.is_err() {
                return;
            }
        }
    }
}

/// Decode `bytes` and answer each complete message.
///
/// Mining channel messages need a connection that set up the Mining Protocol
/// on a listener with mining enabled; anything else is an error that closes
/// the connection.
async fn handle_bytes(
    connection: &mut Sv2Connection,
    mut channels: Option<&mut MiningChannels>,
    mut template_rx: Option<&mut TemplateReceiver>,
    bytes: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let messages = connection.decode(bytes)?;
    let mut frames = Vec::with_capacity(messages.len());
    for (message_type, mut payload) in messages {
        let responses = if is_mining_channel_message(message_type) {
            let channels = match (channels.as_mut(), connection.is_mining()) {
                (Some(channels), true) => channels,
                (Some(_), false) => return Err("mining channel before Mining setup".to_string()),
                (None, _) => return Err("mining channels are not enabled".to_string()),
            };
            let current = template_rx
                .as_mut()
                .and_then(|receiver| receiver.borrow_and_update().clone());
            channels.handle(message_type, &mut payload, current).await?
        } else {
            connection.handle_message(message_type, &mut payload)?
        };
        frames.extend(responses);
    }
    Ok(frames)
}

/// Wait for the next prepared template. Never resolves without a template
/// watch, or once the notifier has dropped its sender.
async fn next_template(
    template_rx: Option<&mut TemplateReceiver>,
) -> Option<Arc<PreparedNotifyParams>> {
    match template_rx {
        Some(receiver) => match receiver.changed().await {
            Ok(()) => receiver.borrow_and_update().clone(),
            Err(_) => future::pending().await,
        },
        None => future::pending().await,
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
            None,
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
