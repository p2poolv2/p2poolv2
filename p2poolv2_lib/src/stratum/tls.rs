// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional TLS listener for the stratum server.
//!
//! The certificate chain and private key are read from PEM files at startup
//! and re-read whenever the files change, so a renewed certificate needs no
//! restart. The current key travels from the reload task to the handshake
//! through a `tokio::sync::watch` channel: the resolver clones the current
//! `Arc` on every handshake, so no lock is taken on the accept path.

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::server::ClientHello;
use tokio_rustls::rustls::server::ResolvesServerCert;
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::server::TlsStream;
use tracing::debug;
use tracing::info;
use tracing::warn;

/// How often the certificate and key files are checked for changes.
pub const CERTIFICATE_RELOAD_INTERVAL: Duration = Duration::from_secs(60);

/// How long a client has to complete the TLS handshake.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Error loading or reloading the TLS certificate chain and private key.
///
/// The message names the file and the reason. It never contains key bytes.
#[derive(Debug, Clone)]
pub struct TlsError {
    pub message: String,
}

impl std::error::Error for TlsError {}

impl std::fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

/// Settings for the optional TLS stratum listener.
#[derive(Debug, Clone)]
pub struct StratumTlsConfig {
    /// The port the TLS listener binds to. Must differ from the plain port.
    pub port: u16,
    /// PEM certificate chain, for example a Let's Encrypt `fullchain.pem`.
    pub cert_path: PathBuf,
    /// PEM private key, for example a Let's Encrypt `privkey.pem`.
    pub key_path: PathBuf,
}

/// Read the PEM certificate chain and private key and check that they match.
///
/// The error names the file and the reason. Key bytes are never printed.
pub fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<CertifiedKey>, TlsError> {
    let certificate_chain = read_certificate_chain(cert_path)?;
    let private_key = read_private_key(key_path)?;
    let provider = aws_lc_rs::default_provider();
    let certified_key =
        CertifiedKey::from_der(certificate_chain, private_key, &provider).map_err(|error| {
            let key_display = key_path.display();
            let cert_display = cert_path.display();
            TlsError {
                message: format!("Key {key_display} does not match {cert_display}: {error}"),
            }
        })?;
    Ok(Arc::new(certified_key))
}

/// Read every certificate in the PEM chain at `cert_path`.
fn read_certificate_chain(cert_path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certificates = CertificateDer::pem_file_iter(cert_path)
        .map_err(|error| TlsError {
            message: format!("Failed to read {}: {error}", cert_path.display()),
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TlsError {
            message: format!("Failed to parse {}: {error}", cert_path.display()),
        })?;
    if certificates.is_empty() {
        return Err(TlsError {
            message: format!("No certificates in {}", cert_path.display()),
        });
    }
    Ok(certificates)
}

/// Read the PEM private key at `key_path`.
fn read_private_key(key_path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    PrivateKeyDer::from_pem_file(key_path).map_err(|error| TlsError {
        message: format!("Failed to read {}: {error}", key_path.display()),
    })
}

/// Serves whatever certificate the reload task last published.
///
/// Holds a `watch::Receiver` rather than a lock: `resolve` clones the current
/// `Arc`, which is a pointer copy, so a handshake never waits on the reloader.
pub struct ReloadingCertificateResolver {
    current: watch::Receiver<Arc<CertifiedKey>>,
}

impl ReloadingCertificateResolver {
    /// Build a resolver that serves whatever key the reloader last published.
    pub fn new(current: watch::Receiver<Arc<CertifiedKey>>) -> Self {
        Self { current }
    }

    /// The DER of the leaf certificate currently being served, if any.
    pub fn current_certificate_der(&self) -> Option<Vec<u8>> {
        self.current
            .borrow()
            .cert
            .first()
            .map(|certificate| certificate.as_ref().to_vec())
    }
}

impl std::fmt::Debug for ReloadingCertificateResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReloadingCertificateResolver")
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for ReloadingCertificateResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.borrow().clone())
    }
}

/// Modification time and length of one watched file.
///
/// Comparing both catches a renewal that keeps the same length, and a rewrite
/// that lands within the filesystem's timestamp granularity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    modified: Option<SystemTime>,
    length: u64,
}

/// The modification time and length of `path`, or `None` when it cannot be read.
fn stamp_of(path: &Path) -> Option<FileStamp> {
    let metadata = fs::metadata(path).ok()?;
    Some(FileStamp {
        modified: metadata.modified().ok(),
        length: metadata.len(),
    })
}

/// The stamps of the certificate and key files, recorded before the initial load.
///
/// Hand this to `spawn_certificate_reloader` so a renewal that lands between
/// the load and the start of the reload task is still seen as a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateFileStamps {
    certificate: Option<FileStamp>,
    key: Option<FileStamp>,
}

/// Record the current stamps of the certificate and key files.
///
/// Call this before `load_certified_key` and pass the result to
/// `spawn_certificate_reloader`: a renewal that lands after the stamps were
/// taken then differs from the recorded stamps and is loaded on the next tick.
pub fn certificate_file_stamps(cert_path: &Path, key_path: &Path) -> CertificateFileStamps {
    CertificateFileStamps {
        certificate: stamp_of(cert_path),
        key: stamp_of(key_path),
    }
}

/// Start the task that reloads the certificate and key when the files change.
///
/// Returns the receiver the resolver reads. The task stops once every receiver
/// is dropped, so it ends with the server. `initial_stamps` must be recorded
/// with `certificate_file_stamps` before the initial load, so a renewal that
/// lands during startup is still seen as a change.
pub fn spawn_certificate_reloader(
    cert_path: PathBuf,
    key_path: PathBuf,
    initial_stamps: CertificateFileStamps,
    initial_key: Arc<CertifiedKey>,
    interval: Duration,
) -> watch::Receiver<Arc<CertifiedKey>> {
    let (sender, receiver) = watch::channel(initial_key);
    tokio::spawn(run_certificate_reloader(
        cert_path,
        key_path,
        sender,
        interval,
        initial_stamps.certificate,
        initial_stamps.key,
    ));
    receiver
}

/// Re-read the certificate and key whenever their stamps change.
///
/// A failed reload logs a warning and keeps the previous key, so a half
/// written renewal never takes the listener down. The stamps are only
/// advanced on success, so a partially written pair is retried next tick.
async fn run_certificate_reloader(
    cert_path: PathBuf,
    key_path: PathBuf,
    sender: watch::Sender<Arc<CertifiedKey>>,
    interval: Duration,
    initial_certificate_stamp: Option<FileStamp>,
    initial_key_stamp: Option<FileStamp>,
) {
    let mut last_certificate_stamp = initial_certificate_stamp;
    let mut last_key_stamp = initial_key_stamp;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = sender.closed() => {
                info!("TLS certificate reloader stopping, no listener is left");
                return;
            }
            _ = ticker.tick() => {
                let certificate_stamp = stamp_of(&cert_path);
                let key_stamp = stamp_of(&key_path);
                let files_changed = certificate_stamp != last_certificate_stamp
                    || key_stamp != last_key_stamp;
                if files_changed {
                    match load_certified_key(&cert_path, &key_path) {
                        Ok(certified_key) => {
                            last_certificate_stamp = certificate_stamp;
                            last_key_stamp = key_stamp;
                            info!("Reloaded TLS certificate from {}", cert_path.display());
                            if sender.send(certified_key).is_err() {
                                return;
                            }
                        }
                        Err(error) => {
                            warn!("Keeping the previous TLS certificate: {error}");
                        }
                    }
                }
            }
        }
    }
}

/// Build the acceptor the TLS listener hands every new connection to.
///
/// TLS 1.2 and 1.3 with the safe defaults, no client authentication and no
/// ALPN: a miner speaks stratum over the tunnel, nothing else. The provider is
/// passed explicitly so no process-global default is installed.
pub fn build_tls_acceptor(
    current_key: watch::Receiver<Arc<CertifiedKey>>,
) -> Result<TlsAcceptor, TlsError> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let resolver = Arc::new(ReloadingCertificateResolver::new(current_key));
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| TlsError {
            message: format!("Failed to select the TLS protocol versions: {error}"),
        })?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Complete the TLS handshake, giving the client `handshake_timeout` to do so.
///
/// Returns `None` when the handshake fails or times out; the caller drops the
/// connection and its semaphore permit.
pub async fn complete_handshake(
    tls_acceptor: TlsAcceptor,
    stream: TcpStream,
    handshake_timeout: Duration,
    addr: SocketAddr,
) -> Option<TlsStream<TcpStream>> {
    match tokio::time::timeout(handshake_timeout, tls_acceptor.accept(stream)).await {
        Ok(Ok(tls_stream)) => Some(tls_stream),
        Ok(Err(error)) => {
            debug!("TLS handshake with {} failed: {}", addr, error);
            None
        }
        Err(_) => {
            debug!("TLS handshake with {} timed out", addr);
            None
        }
    }
}

#[cfg(test)]
mod test_utils {
    use super::*;
    use rcgen::generate_simple_self_signed;

    /// Write a freshly generated self-signed certificate and key to `directory`.
    ///
    /// Returns the certificate path, the key path and the certificate DER, so a
    /// test can compare what the resolver serves against what it wrote.
    pub fn write_certificate_pair(
        directory: &Path,
        names: Vec<String>,
        file_stem: &str,
    ) -> (PathBuf, PathBuf, Vec<u8>) {
        let certified = generate_simple_self_signed(names).unwrap();
        let cert_path = directory.join(format!("{file_stem}.pem"));
        let key_path = directory.join(format!("{file_stem}.key"));
        fs::write(&cert_path, certified.cert.pem()).unwrap();
        fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();
        (cert_path, key_path, certified.cert.der().as_ref().to_vec())
    }

    /// Poll `resolver` until it serves `expected_der` or five seconds pass.
    pub async fn wait_for_certificate(
        resolver: &ReloadingCertificateResolver,
        expected_der: &[u8],
    ) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if resolver.current_certificate_der().as_deref() == Some(expected_der) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::wait_for_certificate;
    use super::test_utils::write_certificate_pair;
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::rustls::RootCertStore;
    use tokio_rustls::rustls::pki_types::ServerName;

    #[test]
    fn generated_certificate_and_key_load() {
        let directory = tempfile::tempdir().unwrap();
        let (cert_path, key_path, certificate_der) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "a");

        let certified_key = load_certified_key(&cert_path, &key_path).unwrap();

        assert_eq!(certified_key.cert.len(), 1);
        assert_eq!(certified_key.cert[0].as_ref(), certificate_der.as_slice());
    }

    #[test]
    fn key_that_does_not_match_the_certificate_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let (cert_path, _, _) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "a");
        let (_, other_key_path, _) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "b");

        let error = load_certified_key(&cert_path, &other_key_path).unwrap_err();

        assert!(
            error.message.contains("does not match"),
            "unexpected message: {}",
            error.message
        );
    }

    #[test]
    fn missing_certificate_file_is_rejected_with_its_path() {
        let directory = tempfile::tempdir().unwrap();
        let (_, key_path, _) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "a");
        let missing_cert_path = directory.path().join("missing.pem");

        let error = load_certified_key(&missing_cert_path, &key_path).unwrap_err();

        assert!(
            error.message.contains("missing.pem"),
            "unexpected message: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn reloader_serves_the_new_certificate_after_the_files_change() {
        let directory = tempfile::tempdir().unwrap();
        let (cert_path, key_path, first_der) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "a");
        let initial_stamps = certificate_file_stamps(&cert_path, &key_path);
        let initial_key = load_certified_key(&cert_path, &key_path).unwrap();
        let current_key = spawn_certificate_reloader(
            cert_path.clone(),
            key_path.clone(),
            initial_stamps,
            initial_key,
            Duration::from_millis(10),
        );
        let resolver = ReloadingCertificateResolver::new(current_key);
        assert_eq!(resolver.current_certificate_der(), Some(first_der));

        let (second_cert_path, second_key_path, second_der) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "b");
        fs::copy(&second_cert_path, &cert_path).unwrap();
        fs::copy(&second_key_path, &key_path).unwrap();

        let reloaded = wait_for_certificate(&resolver, &second_der).await;

        assert!(reloaded, "resolver should serve the new certificate");
    }

    #[tokio::test]
    async fn reloader_loads_a_renewal_that_lands_during_startup() {
        let directory = tempfile::tempdir().unwrap();
        let (cert_path, key_path, first_der) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "a");
        // start_tls_listener records the stamps before it loads the key.
        let initial_stamps = certificate_file_stamps(&cert_path, &key_path);
        let initial_key = load_certified_key(&cert_path, &key_path).unwrap();
        assert_eq!(initial_key.cert[0].as_ref(), first_der.as_slice());

        // A renewal lands after the load but before the reloader starts.
        let (second_cert_path, second_key_path, second_der) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "b");
        fs::copy(&second_cert_path, &cert_path).unwrap();
        fs::copy(&second_key_path, &key_path).unwrap();

        let current_key = spawn_certificate_reloader(
            cert_path.clone(),
            key_path.clone(),
            initial_stamps,
            initial_key,
            Duration::from_millis(10),
        );
        let resolver = ReloadingCertificateResolver::new(current_key);

        let reloaded = wait_for_certificate(&resolver, &second_der).await;

        assert!(
            reloaded,
            "a renewal that lands during startup must be loaded"
        );
    }

    #[tokio::test]
    async fn reloader_keeps_the_previous_certificate_when_the_new_one_is_unparsable() {
        let directory = tempfile::tempdir().unwrap();
        let (cert_path, key_path, first_der) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "a");
        let initial_stamps = certificate_file_stamps(&cert_path, &key_path);
        let initial_key = load_certified_key(&cert_path, &key_path).unwrap();
        let current_key = spawn_certificate_reloader(
            cert_path.clone(),
            key_path.clone(),
            initial_stamps,
            initial_key,
            Duration::from_millis(10),
        );
        let resolver = ReloadingCertificateResolver::new(current_key);

        fs::write(&cert_path, b"not a certificate").unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(resolver.current_certificate_der(), Some(first_der));

        // A valid renewal after the failed one must still be loaded: the
        // reloader has to survive the parse error.
        let (second_cert_path, second_key_path, second_der) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "b");
        fs::copy(&second_cert_path, &cert_path).unwrap();
        fs::copy(&second_key_path, &key_path).unwrap();

        let reloaded = wait_for_certificate(&resolver, &second_der).await;

        assert!(
            reloaded,
            "the reloader must survive a failed reload and load the next valid certificate"
        );
    }

    #[tokio::test]
    async fn client_that_trusts_the_certificate_completes_the_handshake() {
        let directory = tempfile::tempdir().unwrap();
        let (cert_path, key_path, certificate_der) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "a");
        let initial_key = load_certified_key(&cert_path, &key_path).unwrap();
        let (_sender, receiver) = watch::channel(initial_key);
        let tls_acceptor = build_tls_acceptor(receiver).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls_stream = tls_acceptor.accept(stream).await.unwrap();
            let mut buffer = [0u8; 5];
            tls_stream.read_exact(&mut buffer).await.unwrap();
            tls_stream.write_all(&buffer).await.unwrap();
        });

        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(certificate_der))
            .unwrap();
        let provider = Arc::new(aws_lc_rs::default_provider());
        let builder = ClientConfig::builder_with_provider(provider);
        let builder = builder.with_safe_default_protocol_versions().unwrap();
        let client_config = builder
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("localhost").unwrap();
        let stream = TcpStream::connect(address).await.unwrap();
        let mut client_stream = connector.connect(server_name, stream).await.unwrap();
        client_stream.write_all(b"hello").await.unwrap();
        let mut buffer = [0u8; 5];
        client_stream.read_exact(&mut buffer).await.unwrap();

        assert_eq!(&buffer, b"hello");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_times_out_when_the_client_sends_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let (cert_path, key_path, _) =
            write_certificate_pair(directory.path(), vec!["localhost".to_string()], "a");
        let initial_key = load_certified_key(&cert_path, &key_path).unwrap();
        let (_sender, receiver) = watch::channel(initial_key);
        let tls_acceptor = build_tls_acceptor(receiver).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let stream = TcpStream::connect(address).await.unwrap();
            // Hold the connection open far longer than the handshake timeout,
            // so the handshake can only end through the timeout, never EOF.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        let (stream, addr) = listener.accept().await.unwrap();

        let handshake = tokio::time::timeout(
            Duration::from_secs(2),
            complete_handshake(tls_acceptor, stream, Duration::from_millis(50), addr),
        )
        .await
        .expect("the handshake must time out well before the client closes");

        assert!(handshake.is_none());
        client_task.abort();
    }
}
