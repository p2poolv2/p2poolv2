#[cfg(not(unix))]
use tokio::sync;
///! Signal handlers for the node
use tokio::{
    signal::unix::{self, SignalKind},
    sync::watch::Sender,
    task::JoinHandle,
};
use tracing::info;

pub fn setup_signal_handler(exit_sender: Sender<bool>) -> JoinHandle<()> {
    let mut exit_receiver = exit_sender.subscribe();
    // future: improve this by implementing sigterm. Maybe usr1 and 2 for things like committing to disk
    tokio::spawn(async move {
        let mut hangup = listen_signal(SignalKind::hangup());
        let mut terminate = listen_signal(SignalKind::terminate());

        let sig = tokio::select! {
            _ = exit_receiver.changed() => None,
            _ = tokio::signal::ctrl_c() => Some(SignalKind::interrupt()),
            _ = hangup.recv() => Some(SignalKind::hangup()),
            _ = terminate.recv() => Some(SignalKind::terminate()),
        };

        match sig {
            Some(sig) => {
                info!("Received signal {sig:?}. Stopping...");

                exit_sender
                    .send(true)
                    .expect("failed to set shutdown signal");
            }
            None => return,
        }
    })
}

#[cfg(unix)]
fn listen_signal(sig_kind: SignalKind) -> unix::Signal {
    unix::signal(sig_kind).expect("Failed to listen to signal")
}

#[cfg(not(unix))]
fn listen_signal(_: SignalKind) -> io::Result<sync::mpsc::Receiver<()>> {
    // these signals don't map to windows. So we return a "noop" stream
    let (_, rx) = sync::mpsc::channel(1);
    Ok(rx)
}
