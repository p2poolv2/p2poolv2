// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Local Stratum V2 listener.
//!
//! Connections use authenticated Noise when an authority is configured.
//! Job Declaration
//! and Mining are separate connections that share one [`super::JobRegistry`].
//! A Mining connection may also open standard and extended channels, which
//! get a job for every template the SV1 server sees (see `super::mining`).

use super::mining::{MiningChannels, custom_job_error, is_mining_channel_message};
use super::noise::NoiseTransport;
use super::session::{JobRegistry, PoolTransactionCache, Sv2Connection};
use crate::config::Sv2Authority;
use crate::shares::merge_mining::MergeMiningCommitment;
use crate::stratum::server::StratumContext;
use crate::stratum::work::prepared_notify::PreparedNotifyParams;
use binary_sv2::Deserialize;
use mining_sv2::{MESSAGE_TYPE_SET_CUSTOM_MINING_JOB, SetCustomMiningJob};
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
    'connection: loop {
        let frames = tokio::select! {
            read = reader.read(&mut buffer) => {
                let count = match read {
                    Ok(0) | Err(_) => break,
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
                    Err(_) => break,
                }
            }
            prepared = next_template(template_rx.as_mut()) => {
                match (prepared, channels.as_mut()) {
                    (Some(prepared), Some(channels)) => channels.on_template(&prepared),
                    _ => Vec::new(),
                }
            }
            _ = shutdown.changed() => break,
        };
        for frame in frames {
            let wire = match noise.as_mut() {
                Some(transport) => match transport.encrypt(frame) {
                    Ok(encrypted) => encrypted,
                    Err(_) => break 'connection,
                },
                None => frame,
            };
            if writer.write_all(&wire).await.is_err() {
                break 'connection;
            }
        }
    }
    if let Some(channels) = channels.as_mut() {
        channels.close_all().await;
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
        let responses = if message_type == MESSAGE_TYPE_SET_CUSTOM_MINING_JOB {
            let request =
                SetCustomMiningJob::from_bytes(&mut payload).map_err(|error| error.to_string())?;
            if !connection.can_select_work() {
                custom_job_error(&request, "work-selection-not-negotiated")?
            } else if let Some(channels) = channels.as_mut() {
                match connection.take_declared_job(request.token.as_bytes()) {
                    Ok(declared) => {
                        channels
                            .install_custom_job(&request, declared, current_template(template_rx))
                            .await?
                    }
                    Err(_) => custom_job_error(&request, "invalid-mining-job-token")?,
                }
            } else {
                custom_job_error(&request, "mining-unavailable")?
            }
        } else if is_mining_channel_message(message_type) {
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
    use crate::accounting::stats::metrics;
    use crate::config::{Chain, DEFAULT_VERSION_MASK, PoolMode};
    use crate::shares::merge_mining::MergeMiningCommitment;
    use crate::shares::share_block::ShareHeader;
    use crate::stratum::sv2::PoolTransactionCache;
    use crate::stratum::sv2::session::encode_message;
    use crate::stratum::work::tracker::start_tracker_actor;
    use crate::test_utils::{
        TestSv2Client, bch_template_transaction, test_bch_custom_job, test_bch_prepared,
        test_bch_solve_custom_job, test_bch_stratum_context, test_sv2_authority, test_sv2_setup,
    };
    use crate::test_utils::{make_test_share_address, setup_test_chain_store_handle};
    use binary_sv2::U256;
    use binary_sv2::{B016M, B032, B064K, B0255, Seq064K};
    use bitcoin::Network;
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bitcoindrpc::BitcoindRpcClient;
    use codec_sv2::{Handshake, NoiseEncoder};
    use common_messages_sv2::{
        MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol,
        SetupConnection,
    };
    use framing_sv2::framing::SerializedFrame;
    use job_declaration_sv2::{
        AllocateMiningJobToken, AllocateMiningJobTokenSuccess, DeclareMiningJob,
        DeclareMiningJobSuccess, MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
        MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN_SUCCESS, MESSAGE_TYPE_DECLARE_MINING_JOB,
        MESSAGE_TYPE_DECLARE_MINING_JOB_SUCCESS, MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS,
        MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS, ProvideMissingTransactions,
        ProvideMissingTransactionsSuccess,
    };
    use mining_sv2::{
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS, OpenExtendedMiningChannel,
    };
    use mining_sv2::{
        MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR, MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS,
        MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
        OpenExtendedMiningChannelSuccess, SetCustomMiningJobError, SetCustomMiningJobSuccess,
        SubmitSharesExtended, SubmitSharesSuccess,
    };
    use noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};
    use p2poolv2_wallet::bch_share::{BchShareNetwork, encode_payout_address};
    use tokio::sync::mpsc;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_partial_json, method},
    };

    #[tokio::test]
    async fn encrypted_bch_job_declaration_modes_install_mine_and_emit() {
        let rpc = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "getblocktemplate"}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"result": null, "error": null, "id": 0})),
            )
            .expect(1)
            .mount(&rpc)
            .await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"method": "submitblock"}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"result": null, "error": null, "id": 1})),
            )
            .expect(if cfg!(feature = "sim") { 0 } else { 1 })
            .mount(&rpc)
            .await;
        let prepared = test_bch_prepared();
        let cache = PoolTransactionCache::new();
        cache.set_prepared(Arc::clone(&prepared));
        let (_template_sender, template_rx) = watch::channel(Some(Arc::clone(&prepared)));
        let (ctx, mut emissions, _dirs) = test_bch_stratum_context(&rpc.uri()).await;
        let authority = test_sv2_authority();
        let listener = bind("127.0.0.1", 0).await.unwrap();
        let address = listener.local_addr().unwrap();
        let connection_limit = Arc::new(Semaphore::new(3));
        let (shutdown_sender, shutdown_receiver) = watch::channel(());
        let server = tokio::spawn(serve(
            listener,
            Arc::clone(&connection_limit),
            cache,
            Some(MergeMiningCommitment::reserved()),
            Some(Sv2Mining {
                ctx,
                version_mask: DEFAULT_VERSION_MASK,
                template_rx,
            }),
            Some(authority),
            shutdown_receiver,
        ));
        let mut mining = TestSv2Client::connect(address, authority.public_key).await;
        mining
            .send(
                encode_message(
                    test_sv2_setup(Protocol::MiningProtocol, 2),
                    MESSAGE_TYPE_SETUP_CONNECTION,
                )
                .unwrap(),
            )
            .await;
        mining.receive(MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS).await;
        let payout = bitcoin::Address::p2pkh(
            bitcoin::PubkeyHash::from_byte_array([0x22; 20]),
            Network::Regtest,
        );
        let identity = encode_payout_address(&payout, BchShareNetwork::Regtest).unwrap();
        mining
            .send(
                encode_message(
                    OpenExtendedMiningChannel {
                        request_id: 1,
                        user_identity: identity.as_str().try_into().unwrap(),
                        nominal_hash_rate: 1.0,
                        max_target: U256::new(&[0xff; 32]).unwrap(),
                        min_extranonce_size: 8,
                    },
                    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                )
                .unwrap(),
            )
            .await;
        let mut open_payload = mining
            .receive(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS)
            .await;
        let open = OpenExtendedMiningChannelSuccess::from_bytes(&mut open_payload).unwrap();
        let extranonce_prefix = open.extranonce_prefix.as_bytes().to_vec();

        let mut declarator = TestSv2Client::connect(address, authority.public_key).await;
        declarator
            .send_pair(
                encode_message(
                    test_sv2_setup(Protocol::JobDeclarationProtocol, 1),
                    MESSAGE_TYPE_SETUP_CONNECTION,
                )
                .unwrap(),
                encode_message(
                    AllocateMiningJobToken {
                        request_id: 2,
                        user_identifier: "miner".try_into().unwrap(),
                    },
                    MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
                )
                .unwrap(),
            )
            .await;
        declarator
            .receive(MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS)
            .await;
        let mut allocation_payload = declarator
            .receive(MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN_SUCCESS)
            .await;
        let allocated = AllocateMiningJobTokenSuccess::from_bytes(&mut allocation_payload).unwrap();
        let token = allocated.mining_job_token.as_bytes().to_vec();
        let selected: bitcoin::Transaction =
            deserialize(&hex::decode(bch_template_transaction(1).data).unwrap()).unwrap();
        let (mut custom_bytes, declared) = test_bch_custom_job(
            Arc::clone(&prepared),
            token.clone(),
            vec![selected.clone()],
            true,
            prepared.template().coinbasevalue,
        );
        let declaration = declared.declaration.unwrap();
        let wtxid = selected.compute_wtxid().to_byte_array();
        declarator
            .send(
                encode_message(
                    DeclareMiningJob {
                        request_id: 3,
                        mining_job_token: B0255::new(&token).unwrap(),
                        version: declaration.version,
                        coinbase_tx_prefix: B064K::new(&declaration.prefix).unwrap(),
                        coinbase_tx_suffix: B064K::new(&declaration.suffix).unwrap(),
                        wtxid_list: Seq064K::new(vec![U256::new(&wtxid).unwrap()]).unwrap(),
                        excess_data: B064K::new(&[0; 5000]).unwrap(),
                    },
                    MESSAGE_TYPE_DECLARE_MINING_JOB,
                )
                .unwrap(),
            )
            .await;
        let mut missing_payload = declarator
            .receive(MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS)
            .await;
        let missing = ProvideMissingTransactions::from_bytes(&mut missing_payload).unwrap();
        assert_eq!(missing.request_id, 3);
        assert_eq!(missing.unknown_tx_position_list.as_slice(), &[0]);
        let transaction_bytes = serialize(&selected);
        declarator
            .send(
                encode_message(
                    ProvideMissingTransactionsSuccess {
                        request_id: 3,
                        transaction_list: Seq064K::new(vec![
                            B016M::new(&transaction_bytes).unwrap(),
                        ])
                        .unwrap(),
                    },
                    MESSAGE_TYPE_PROVIDE_MISSING_TRANSACTIONS_SUCCESS,
                )
                .unwrap(),
            )
            .await;
        let mut accepted_payload = declarator
            .receive(MESSAGE_TYPE_DECLARE_MINING_JOB_SUCCESS)
            .await;
        let declared = DeclareMiningJobSuccess::from_bytes(&mut accepted_payload).unwrap();
        let new_token = declared.new_mining_job_token.as_bytes().to_vec();
        let mut custom = SetCustomMiningJob::from_bytes(&mut custom_bytes).unwrap();
        custom.token = B0255::new(&new_token).unwrap();
        let custom_frame =
            encode_message(custom.clone(), MESSAGE_TYPE_SET_CUSTOM_MINING_JOB).unwrap();
        mining.send(custom_frame.clone()).await;
        let mut installed_payload = mining
            .receive(MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS)
            .await;
        let installed = SetCustomMiningJobSuccess::from_bytes(&mut installed_payload).unwrap();
        assert_eq!(installed.request_id, custom.request_id);
        mining.send(custom_frame).await;
        let mut replay_payload = mining
            .receive(MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_ERROR)
            .await;
        let replay = SetCustomMiningJobError::from_bytes(&mut replay_payload).unwrap();
        assert_eq!(
            replay.error_code.as_utf8_or_hex(),
            "invalid-mining-job-token"
        );
        let header = test_bch_solve_custom_job(&custom, &extranonce_prefix);
        mining
            .send(
                encode_message(
                    SubmitSharesExtended {
                        channel_id: 1,
                        sequence_number: 1,
                        job_id: installed.job_id,
                        nonce: header.nonce,
                        ntime: header.time,
                        version: custom.version,
                        extranonce: B032::new(&[0; 8]).unwrap(),
                    },
                    MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
                )
                .unwrap(),
            )
            .await;
        let mut submitted_payload = mining.receive(MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS).await;
        let submitted = SubmitSharesSuccess::from_bytes(&mut submitted_payload).unwrap();
        assert_eq!(submitted.last_sequence_number, 1);
        let emission = emissions.try_recv().unwrap();
        assert_eq!(emission.header, header);
        assert_eq!(
            emission.blocktemplate.transactions[0].txid,
            selected.compute_txid().to_string()
        );
        let share = ShareHeader::from_commitment_and_header(
            emission.share_commitment.unwrap(),
            emission.header,
            u64::from(emission.blocktemplate.height),
            emission.coinbase_proof.unwrap(),
        );
        assert_eq!(
            share
                .coinbase_proof
                .merkle_root(&share, &emission.template_merkle_branches)
                .unwrap(),
            header.merkle_root
        );

        let mut private_declarator = TestSv2Client::connect(address, authority.public_key).await;
        private_declarator
            .send_pair(
                encode_message(
                    test_sv2_setup(Protocol::JobDeclarationProtocol, 0),
                    MESSAGE_TYPE_SETUP_CONNECTION,
                )
                .unwrap(),
                encode_message(
                    AllocateMiningJobToken {
                        request_id: 4,
                        user_identifier: "miner".try_into().unwrap(),
                    },
                    MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN,
                )
                .unwrap(),
            )
            .await;
        private_declarator
            .receive(MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS)
            .await;
        let mut allocation_payload = private_declarator
            .receive(MESSAGE_TYPE_ALLOCATE_MINING_JOB_TOKEN_SUCCESS)
            .await;
        let allocated = AllocateMiningJobTokenSuccess::from_bytes(&mut allocation_payload).unwrap();
        let private_tx =
            deserialize(&hex::decode(bch_template_transaction(9).data).unwrap()).unwrap();
        let (mut private_bytes, _) = test_bch_custom_job(
            Arc::clone(&prepared),
            allocated.mining_job_token.as_bytes().to_vec(),
            vec![private_tx],
            false,
            prepared.template().coinbasevalue,
        );
        let private = SetCustomMiningJob::from_bytes(&mut private_bytes).unwrap();
        mining
            .send(encode_message(private.clone(), MESSAGE_TYPE_SET_CUSTOM_MINING_JOB).unwrap())
            .await;
        let mut installed_payload = mining
            .receive(MESSAGE_TYPE_SET_CUSTOM_MINING_JOB_SUCCESS)
            .await;
        let installed = SetCustomMiningJobSuccess::from_bytes(&mut installed_payload).unwrap();
        let private_header = test_bch_solve_custom_job(&private, &extranonce_prefix);
        mining
            .send(
                encode_message(
                    SubmitSharesExtended {
                        channel_id: 1,
                        sequence_number: 2,
                        job_id: installed.job_id,
                        nonce: private_header.nonce,
                        ntime: private_header.time,
                        version: private.version,
                        extranonce: B032::new(&[0; 8]).unwrap(),
                    },
                    MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED,
                )
                .unwrap(),
            )
            .await;
        let mut submitted_payload = mining.receive(MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS).await;
        let submitted = SubmitSharesSuccess::from_bytes(&mut submitted_payload).unwrap();
        assert_eq!(submitted.last_sequence_number, 2);
        let emission = emissions.try_recv().unwrap();
        assert_eq!(emission.header, private_header);
        assert!(emission.blocktemplate.transactions.is_empty());
        assert_ne!(
            emission.template_merkle_branches[0].as_byte_array(),
            selected.compute_txid().as_byte_array()
        );
        let share = ShareHeader::from_commitment_and_header(
            emission.share_commitment.unwrap(),
            emission.header,
            u64::from(emission.blocktemplate.height),
            emission.coinbase_proof.unwrap(),
        );
        assert_eq!(
            share
                .coinbase_proof
                .merkle_root(&share, &emission.template_merkle_branches)
                .unwrap(),
            private_header.merkle_root
        );
        let received = rpc.received_requests().await.unwrap();
        assert_eq!(received.len(), if cfg!(feature = "sim") { 1 } else { 2 });
        let proposal: serde_json::Value = serde_json::from_slice(&received[0].body).unwrap();
        assert_eq!(proposal["params"][0]["mode"], "proposal");
        drop(mining);
        drop(declarator);
        drop(private_declarator);
        shutdown_sender.send(()).unwrap();
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        let permits = timeout(
            Duration::from_secs(5),
            connection_limit.acquire_many_owned(3),
        )
        .await
        .unwrap()
        .unwrap();
        drop(permits);
    }

    #[tokio::test]
    async fn disconnect_releases_the_authorized_worker_and_connection_permit() {
        let stats_dir = tempfile::tempdir().unwrap();
        let metrics = metrics::start_metrics(stats_dir.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        let (chain_store_handle, _store_dir) = setup_test_chain_store_handle(true).await;
        let (emissions_tx, _emissions_rx) = mpsc::channel(10);
        let ctx = StratumContext {
            tracker_handle: start_tracker_actor(),
            bitcoindrpc_client: BitcoindRpcClient::new("http://127.0.0.1:1", "user", "pass")
                .unwrap(),
            start_difficulty: 1,
            minimum_difficulty: 1,
            maximum_difficulty: None,
            ignore_difficulty: true,
            validate_addresses: true,
            emissions_tx,
            network: Network::Signet,
            metrics: metrics.clone(),
            chain_store_handle,
            mode: PoolMode::P2poolv2,
            miner_address: Some(make_test_share_address(1, Network::Signet)),
            share_chain: Chain::Bitcoin,
            bch_share_network: None,
            cash_share: None,
        };
        let listener = bind("127.0.0.1", 0).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let registry = Arc::new(Mutex::new(JobRegistry::new(
            PoolTransactionCache::new(),
            None,
        )));
        let connection_limit = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&connection_limit).acquire_owned().await.unwrap();
        let (_template_sender, template_rx) = watch::channel(None);
        let (_shutdown_sender, shutdown_rx) = watch::channel(());
        let connection = tokio::spawn(handle_connection(
            stream,
            permit,
            Arc::clone(&registry),
            Some(Sv2Mining {
                ctx,
                version_mask: DEFAULT_VERSION_MASK,
                template_rx,
            }),
            None,
            shutdown_rx,
        ));
        let setup = encode_message(
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
        )
        .unwrap();
        client.write_all(&setup).await.unwrap();
        let payout = "tb1q3udk7r26qs32ltf9nmqrjaaa7tr55qmkk30q5d";
        let username = format!("{payout}.rig1");
        let open = encode_message(
            OpenExtendedMiningChannel {
                request_id: 1,
                user_identity: username.as_str().try_into().unwrap(),
                nominal_hash_rate: 1.0,
                max_target: U256::new(&[0xff; 32]).unwrap(),
                min_extranonce_size: 8,
            },
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
        )
        .unwrap();
        client.write_all(&open).await.unwrap();
        let mut decoder = Sv2Connection::new(registry);
        timeout(Duration::from_secs(5), async {
            let mut opened = false;
            let mut buffer = [0u8; 512];
            while !opened {
                let count = client.read(&mut buffer).await.unwrap();
                assert_ne!(count, 0);
                opened =
                    decoder
                        .decode(&buffer[..count])
                        .unwrap()
                        .iter()
                        .any(|(message_type, _)| {
                            *message_type == MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS
                        });
            }
        })
        .await
        .unwrap();
        assert!(metrics.get_metrics().await.users[payout].workers["rig1"].active);
        drop(client);
        timeout(Duration::from_secs(5), connection)
            .await
            .unwrap()
            .unwrap();
        assert!(!metrics.get_metrics().await.users[payout].workers["rig1"].active);
        assert_eq!(connection_limit.available_permits(), 1);
    }

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
        let authority = test_sv2_authority();
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

        let mut client = TestSv2Client::connect(address, authority.public_key).await;
        client
            .send_message(
                MESSAGE_TYPE_SETUP_CONNECTION,
                test_sv2_setup(Protocol::MiningProtocol, 0),
            )
            .await;
        client.receive(MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS).await;

        shutdown_sender.send(()).unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_client_pinning_another_authority_key_rejects_the_handshake() {
        let authority = test_sv2_authority();
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
