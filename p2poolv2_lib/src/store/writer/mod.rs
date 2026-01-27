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

//! Store writer for serialized database writes.
//!
//! This module provides a dedicated task for processing all Store write
//! operations sequentially. Reads are direct via Arc<Store>, while writes
//! go through a channel to ensure serialization.

mod handle;

pub use handle::StoreHandle;

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::shares::share_block::ShareBlock;
use crate::store::Store;
use bitcoin::{BlockHash, Work};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};

/// Channel buffer size for write commands
pub const WRITE_CHANNEL_SIZE: usize = 100;

/// Error type for store operations
#[derive(Debug, Clone)]
pub enum StoreError {
    /// Database error
    Database(String),
    /// Channel closed
    ChannelClosed,
    /// Item not found
    NotFound(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Database(msg) => write!(f, "Database error: {msg}"),
            StoreError::ChannelClosed => write!(f, "Channel closed"),
            StoreError::NotFound(msg) => write!(f, "Not found: {msg}"),
        }
    }
}

impl Error for StoreError {}

/// Commands for write operations on the Store.
///
/// Each command that needs a response includes a oneshot sender.
/// Fire-and-forget commands (like SetChainTip) don't need responses.
#[derive(Debug)]
pub enum WriteCommand {
    /// Add a share to the store
    AddShare {
        share: ShareBlock,
        height: u32,
        chain_work: Work,
        confirm_txs: bool,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },

    /// Setup genesis block
    SetupGenesis {
        genesis: ShareBlock,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },

    /// Initialize chain state from store
    InitChainStateFromStore {
        genesis_hash: BlockHash,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },

    /// Add a job
    AddJob {
        timestamp: u64,
        serialized_notify: String,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },

    /// Add a user
    AddUser {
        btcaddress: String,
        reply: oneshot::Sender<Result<u64, StoreError>>,
    },

    /// Add a PPLNS share
    AddPplnsShare {
        pplns_share: SimplePplnsShare,
        reply: oneshot::Sender<Result<(), StoreError>>,
    },

    /// Set chain tip (fire-and-forget, updates in-memory state)
    SetChainTip { hash: BlockHash },

    /// Set genesis block hash (fire-and-forget)
    SetGenesisBlockHash { hash: BlockHash },

    /// Update all tips (fire-and-forget)
    UpdateTips { tips: HashSet<BlockHash> },

    /// Add a tip (fire-and-forget)
    AddTip { hash: BlockHash },

    /// Remove a tip (fire-and-forget)
    RemoveTip { hash: BlockHash },
}

/// Sender type for write commands
pub type WriteSender = mpsc::Sender<WriteCommand>;

/// Receiver type for write commands
pub type WriteReceiver = mpsc::Receiver<WriteCommand>;

/// Create a new write channel
pub fn write_channel() -> (WriteSender, WriteReceiver) {
    mpsc::channel(WRITE_CHANNEL_SIZE)
}

/// Store writer that processes write commands sequentially.
///
/// This ensures all writes to RocksDB are serialized, avoiding
/// concurrent write conflicts while allowing direct reads.
pub struct StoreWriter {
    store: Arc<Store>,
    command_rx: WriteReceiver,
}

impl StoreWriter {
    /// Create a new store writer
    pub fn new(store: Arc<Store>, command_rx: WriteReceiver) -> Self {
        Self { store, command_rx }
    }

    /// Run the writer event loop until the channel is closed
    pub async fn run(mut self) {
        info!("Store writer started");

        while let Some(cmd) = self.command_rx.recv().await {
            self.handle_command(cmd);
        }

        info!("Store writer stopped - channel closed");
    }

    /// Handle a single write command
    fn handle_command(&self, cmd: WriteCommand) {
        match cmd {
            WriteCommand::AddShare {
                share,
                height,
                chain_work,
                confirm_txs,
                reply,
            } => {
                debug!("Writing share: {:?}", share.block_hash());
                let mut batch = Store::get_write_batch();
                let result = self
                    .store
                    .add_share(&share, height, chain_work, confirm_txs, &mut batch)
                    .and_then(|_| {
                        self.store
                            .commit_batch(batch)
                            .map_err(|e| e.to_string().into())
                    });
                let _ = reply.send(result.map_err(|e| StoreError::Database(e.to_string())));
            }

            WriteCommand::SetupGenesis { genesis, reply } => {
                debug!("Setting up genesis: {:?}", genesis.block_hash());
                let mut batch = Store::get_write_batch();
                let result = self
                    .store
                    .setup_genesis(&genesis, &mut batch)
                    .and_then(|_| {
                        self.store
                            .commit_batch(batch)
                            .map_err(|e| e.to_string().into())
                    });
                let _ = reply.send(result.map_err(|e| StoreError::Database(e.to_string())));
            }

            WriteCommand::InitChainStateFromStore {
                genesis_hash,
                reply,
            } => {
                debug!("Initializing chain state from store");
                let result = self.store.init_chain_state_from_store(genesis_hash);
                let _ = reply.send(result.map_err(|e| StoreError::Database(e.to_string())));
            }

            WriteCommand::AddJob {
                timestamp,
                serialized_notify,
                reply,
            } => {
                debug!("Adding job: {}", timestamp);
                let result = self.store.add_job(timestamp, serialized_notify);
                let _ = reply.send(result.map_err(|e| StoreError::Database(e.to_string())));
            }

            WriteCommand::AddUser { btcaddress, reply } => {
                debug!("Adding user: {}", btcaddress);
                let result = self.store.add_user(btcaddress);
                let _ = reply.send(result.map_err(|e| StoreError::Database(e.to_string())));
            }

            WriteCommand::AddPplnsShare { pplns_share, reply } => {
                debug!("Adding PPLNS share for user: {}", pplns_share.user_id);
                let result = self.store.add_pplns_share(pplns_share);
                let _ = reply.send(result.map_err(|e| StoreError::Database(e.to_string())));
            }

            // Fire-and-forget commands (in-memory state updates)
            WriteCommand::SetChainTip { hash } => {
                self.store.set_chain_tip(hash);
            }

            WriteCommand::SetGenesisBlockHash { hash } => {
                self.store.set_genesis_blockhash(hash);
            }

            WriteCommand::UpdateTips { tips } => {
                self.store.update_tips(tips);
            }

            WriteCommand::AddTip { hash } => {
                self.store.add_tip(hash);
            }

            WriteCommand::RemoveTip { hash } => {
                self.store.remove_tip(&hash);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_error_display() {
        let err = StoreError::Database("test error".to_string());
        assert_eq!(format!("{err}"), "Database error: test error");

        let err = StoreError::ChannelClosed;
        assert_eq!(format!("{err}"), "Channel closed");

        let err = StoreError::NotFound("block".to_string());
        assert_eq!(format!("{err}"), "Not found: block");
    }

    #[test]
    fn test_write_channel_creation() {
        let (tx, _rx) = write_channel();
        assert!(!tx.is_closed());
    }
}
