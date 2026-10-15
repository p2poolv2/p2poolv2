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
use super::noise::NoiseTransport;
use super::session::{JobRegistry, PoolTransactionCache, Sv2Connection};
use crate::config::Sv2Authority;
use crate::shares::merge_mining::MergeMiningCommitment;
use crate::stratum::server::StratumContext;
use crate::stratum::work::prepared_notify::PreparedNotifyParams;
use std::future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::timeout;
use tracing::{debug, error, info};

/// Time a client has to complete the Noise handshake after connecting.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
/// `None` when the listener only speaks Job Declaration. With `authority`,
/// every connection must complete the Noise NX handshake signed by that key
/// before any message; without it frames are unencrypted, which the
/// specification allows only between local roles. A failed accept is logged
/// and the listener keeps serving, as the SV1 server does.
///
/// Each connection holds a permit from `connection_limit`, the semaphore the
/// SV1 server takes its own permits from, so the two ports share one
/// connection cap. A connection arriving with no permit left is closed.
pub(crate) async fn serve<ShutdownSignal>(
    listener: TcpListener,
    connection_limit: Arc<Semaphore>,
    pool_transactions: PoolTransactionCache,
    merge_mining: Option<MergeMiningCommitment>,
    mining: Option<Sv2Mining>,
    authority: Option<Sv2Authority>,
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
                    Ok((stream, peer)) => {
                        let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                debug!("Stratum connection limit reached, rejecting SV2 {peer}");
                                continue;
                            }
                        };
                        let connection_mining = mining.as_ref().map(|services| Sv2Mining {
                            ctx: services.ctx.clone(),
                            version_mask: services.version_mask,
                            template_rx: services.template_rx.clone(),
                        });
                        tokio::spawn(handle_connection(
                            stream,
                            permit,
                            Arc::clone(&registry),
                            connection_mining,
                            authority,
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

/// Serve one connection until it closes, fails, or the listener stops.
///
/// `_permit` is the connection's place under the shared cap, released when
/// this returns. A Noise handshake that does not finish within
/// [`HANDSHAKE_TIMEOUT`] closes the connection, so an idle socket cannot
/// hold a permit before it has proven it speaks SV2.
async fn handle_connection<ShutdownSignal>(
    mut stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    registry: Arc<Mutex<JobRegistry>>,
    mining: Option<Sv2Mining>,
    authority: Option<Sv2Authority>,
    mut shutdown: watch::Receiver<ShutdownSignal>,
) {
    let mut noise = match authority {
        Some(authority) => {
            match timeout(
                HANDSHAKE_TIMEOUT,
                NoiseTransport::accept(&mut stream, &authority),
            )
            .await
            {
                Ok(Ok(transport)) => Some(transport),
                Ok(Err(handshake_error)) => {
                    debug!("Stratum V2 handshake failed: {handshake_error}");
                    return;
                }
                Err(_) => {
                    debug!("Stratum V2 handshake timed out");
                    return;
                }
            }
        }
        None => None,
    };
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
                let messages = match noise.as_mut() {
                    Some(transport) => transport.decode(&buffer[..count]),
                    None => connection.decode(&buffer[..count]),
                };
                let handled = match messages {
                    Ok(messages) => {
                        handle_messages(
                            &mut connection,
                            channels.as_mut(),
                            template_rx.as_ref(),
                            messages,
                        )
                        .await
                    }
                    Err(decode_error) => Err(decode_error),
                };
                match handled {
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
            let wire = match noise.as_mut() {
                Some(transport) => match transport.encrypt(frame) {
                    Ok(encrypted) => encrypted,
                    Err(_) => return,
                },
                None => frame,
            };
            if writer.write_all(&wire).await.is_err() {
                return;
            }
        }
    }
}

/// Answer each complete message.
///
/// Mining channel messages need a connection that set up the Mining Protocol
/// on a listener with mining enabled; anything else is an error that closes
/// the connection.
async fn handle_messages(
    connection: &mut Sv2Connection,
    mut channels: Option<&mut MiningChannels>,
    template_rx: Option<&TemplateReceiver>,
    messages: Vec<(u8, Vec<u8>)>,
) -> Result<Vec<Vec<u8>>, String> {
    let mut frames = Vec::with_capacity(messages.len());
    for (message_type, mut payload) in messages {
        let responses = if is_mining_channel_message(message_type) {
            let channels = match (channels.as_mut(), connection.is_mining()) {
                (Some(channels), true) => channels,
                (Some(_), false) => return Err("mining channel before Mining setup".to_string()),
                (None, _) => return Err("mining channels are not enabled".to_string()),
            };
            let current = current_template(template_rx);
            channels.handle(message_type, &mut payload, current).await?
        } else {
            connection.handle_message(message_type, &mut payload)?
        };
        frames.extend(responses);
    }
    Ok(frames)
}

/// The latest prepared template, for a new channel's first job.
///
/// Reads without marking the template seen: [`next_template`] must still
/// wake for it so every open channel gets the job. Marking it here dropped
/// a template that arrived while a share submission was being handled, and
/// the connection's channels kept mining the old one.
fn current_template(template_rx: Option<&TemplateReceiver>) -> Option<Arc<PreparedNotifyParams>> {
    template_rx.and_then(|receiver| receiver.borrow().clone())
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
    use crate::config::StratumConfig;
    use crate::stratum::sv2::session::encode_message;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use codec_sv2::{Decrypted, Handshake, NoiseDecoder, NoiseEncoder};
    use common_messages_sv2::{
        MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol,
        SetupConnection,
    };
    use framing_sv2::framing::{MessageFrame, SerializedFrame};
    use noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};

    #[test]
    fn reading_the_current_template_leaves_it_for_next_template() {
        let (sender, receiver): (_, TemplateReceiver) = watch::channel(None);
        sender.send(None).unwrap();
        assert!(current_template(Some(&receiver)).is_none());
        assert!(receiver.has_changed().unwrap());
    }

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
    async fn noise_listener_answers_setup_connection_to_a_client_pinning_its_key() {
        let mut config = StratumConfig::new_for_test_default();
        config.sv2_port = Some(3336);
        config.sv2_authority_public_key =
            Some("9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan".to_string());
        config.sv2_authority_secret_key =
            Some("zmBEmPhqo3A92FkiLVvyCz6htc3e53ph3ZbD4ASqGaLjwnFLi".to_string());
        let authority = config.parse().unwrap().sv2_authority().unwrap();
        let listener = bind("localhost", 0).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_sender, shutdown_receiver) = watch::channel(());
        let server = tokio::spawn(serve(
            listener,
            Arc::new(Semaphore::new(8)),
            PoolTransactionCache::new(),
            None,
            None,
            Some(authority),
            shutdown_receiver,
        ));

        let mut stream = TcpStream::connect(address).await.unwrap();
        let initiator = Initiator::from_raw_k(authority.public_key).unwrap();
        let (hello, waiting) = Handshake::initiator(initiator).step_0().unwrap();
        let mut encoder = NoiseEncoder::new();
        stream
            .write_all(encoder.encode_handshake(hello).as_ref())
            .await
            .unwrap();
        let mut reply = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        stream.read_exact(&mut reply).await.unwrap();
        let (mut encrypt, mut decrypt) = waiting.step_2(reply).unwrap().split();

        let setup = MessageFrame::from_message(
            SetupConnection {
                protocol: Protocol::MiningProtocol,
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
            0,
            false,
        )
        .unwrap();
        let encrypted: Vec<u8> = encoder.encode_transport(setup, &mut encrypt).unwrap();
        stream.write_all(&encrypted).await.unwrap();

        let mut decoder = NoiseDecoder::new();
        let mut response_type = None;
        while response_type.is_none() {
            stream.read_exact(decoder.writable()).await.unwrap();
            match decoder.next_transport_frame(decrypt).unwrap() {
                Decrypted::Frame(frame, state) => {
                    response_type = Some(frame.header().msg_type());
                    decrypt = state;
                }
                Decrypted::Incomplete(_, state) => decrypt = state,
            }
        }
        assert_eq!(response_type, Some(MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS));

        shutdown_sender.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_client_pinning_another_authority_key_rejects_the_handshake() {
        let mut config = StratumConfig::new_for_test_default();
        config.sv2_port = Some(3336);
        config.sv2_authority_public_key =
            Some("9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan".to_string());
        config.sv2_authority_secret_key =
            Some("zmBEmPhqo3A92FkiLVvyCz6htc3e53ph3ZbD4ASqGaLjwnFLi".to_string());
        let authority = config.parse().unwrap().sv2_authority().unwrap();
        let listener = bind("localhost", 0).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_sender, shutdown_receiver) = watch::channel(());
        let server = tokio::spawn(serve(
            listener,
            Arc::new(Semaphore::new(8)),
            PoolTransactionCache::new(),
            None,
            None,
            Some(authority),
            shutdown_receiver,
        ));

        let mut stream = TcpStream::connect(address).await.unwrap();
        // The x-only key of secret 0x01..01: a valid key, but not the authority.
        let other_key = Keypair::from_seckey_slice(&Secp256k1::new(), &[1u8; 32])
            .unwrap()
            .x_only_public_key()
            .0
            .serialize();
        let initiator = Initiator::from_raw_k(other_key).unwrap();
        let (hello, waiting) = Handshake::initiator(initiator).step_0().unwrap();
        let mut encoder = NoiseEncoder::new();
        stream
            .write_all(encoder.encode_handshake(hello).as_ref())
            .await
            .unwrap();
        let mut reply = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        stream.read_exact(&mut reply).await.unwrap();
        assert!(waiting.step_2(reply).is_err());

        shutdown_sender.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn served_listener_answers_setup_connection() {
        let listener = bind("localhost", 0).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_sender, shutdown_receiver) = watch::channel(());
        let server = tokio::spawn(serve(
            listener,
            Arc::new(Semaphore::new(8)),
            PoolTransactionCache::new(),
            Some(MergeMiningCommitment::reserved()),
            None,
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

    #[tokio::test]
    async fn a_connection_over_the_shared_limit_is_closed() {
        let listener = bind("localhost", 0).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_sender, shutdown_receiver) = watch::channel(());
        let server = tokio::spawn(serve(
            listener,
            Arc::new(Semaphore::new(0)),
            PoolTransactionCache::new(),
            Some(MergeMiningCommitment::reserved()),
            None,
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
        let _ = stream.write_all(&setup).await;
        let mut response = vec![0u8; 64];
        let read = stream.read(&mut response).await.unwrap_or(0);
        assert_eq!(read, 0, "a connection without a permit gets no reply");

        shutdown_sender.send(()).unwrap();
        server.await.unwrap();
    }
}
