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

use crate::error::Error;
use bitcoin::secp256k1::rand::{self, RngCore};
use bitcoin::{bip152::HeaderAndShortIds, p2p::message_compact_blocks::CmpctBlock, Block};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::warn;

/// Use compact block version 2 to support segwit
const COMPACT_BLOCK_VERSION: u32 = 2;

/// Struct that is serialized into share store.
/// This is not used for stratum communication, but is stored in the db for share accounting.
#[derive(Debug, Serialize, Deserialize)]
pub struct StratumShare {
    /// A job id to track this job and used to find the shares for it later
    pub job_id: u64,
    /// Username for finding user
    pub username: String,
    /// nonce saved as u32 converted from string
    pub nonce: u32,
    /// extranonce2 saved as u32 converted from string
    pub extranonce2: u32,
    /// ntime saved as u32 converted from string
    pub ntime: u32,
    /// version mask from the session - we ignore different version mask sent in a submit message
    pub version_mask: i32,
}

impl StratumShare {
    /// Create a new StratumShare instance.
    /// This is called after the block has been validated, therefore we trust that the parsing of integers will not fail.
    pub fn new(
        job_id: u64,
        username: &str,
        nonce: &str,
        extranonce2: &str,
        ntime: &str,
        version_mask: i32,
    ) -> Self {
        StratumShare {
            job_id,
            username: username.to_string(),
            nonce: u32::from_str_radix(nonce, 16).unwrap(), // will always succeed, see StratumShare::new
            extranonce2: u32::from_str_radix(extranonce2, 16).unwrap(), // will always succeed, see StratumShare::new
            ntime: u32::from_str_radix(ntime, 16).unwrap(), // will always succeed, see StratumShare::new
            version_mask,
        }
    }
}

/// Create a compact block from a given block
/// Does not prefill any transactions. Coinbase is always prefilled by default.
fn create_compact_block_from_share(block: &Block) -> Result<CmpctBlock, Error> {
    let mut rng = rand::thread_rng();
    let nonce: u64 = rng.next_u64();
    let header_and_short_ids: HeaderAndShortIds =
        HeaderAndShortIds::from_block(block, nonce, COMPACT_BLOCK_VERSION, &[]).map_err(|e| {
            Error::IoError(std::io::Error::other(format!(
                "Failed to create HeaderAndShortIds: {e}"
            )))
        })?;
    let message = CmpctBlock {
        compact_block: header_and_short_ids,
    };
    Ok(message)
}

/// Send a compact block message to the shares tx channel
pub fn send_share_compact_block(
    share_block: &Block,
    shares_tx: mpsc::Sender<CmpctBlock>,
) -> Result<(), Box<dyn std::error::Error>> {
    match create_compact_block_from_share(share_block) {
        Ok(message) => match shares_tx.send(message).await {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!("Error sending compact block to shares channel: {e}");
                Err(Box::new(e))
            }
        },
        Err(e) => {
            warn!("Error creating compact block from share block: {e}");
            Err(Box::new(e))
        }
    }
}

#[cfg(test)]
mod send_share_block_tests {

    use super::*;
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hex::FromHex;

    fn build_test_block() -> Block {
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block_bytes = Vec::from_hex(BLOCK_HEX).unwrap();
        deserialize(&block_bytes).unwrap()
    }

    #[test]
    fn test_creating_compact_block_from_share_block() {
        let block = build_test_block();

        let result = create_compact_block_from_share(&block);
        match result {
            Ok(compact_block) => {
                assert_eq!(compact_block.compact_block.header, block.header);
                assert_eq!(compact_block.compact_block.short_ids.len(), 0);
                assert_eq!(compact_block.compact_block.prefilled_txs.len(), 1);
                assert_eq!(compact_block.compact_block.prefilled_txs[0].idx, 0);
            }
            _ => panic!("Failed to create compact block from share block"),
        }
    }

    #[tokio::test]
    async fn test_send_share_block() {
        let block = build_test_block();

        let (shares_tx, mut shares_rx) = mpsc::channel(1);
        let result = send_share_compact_block(&block, shares_tx);

        assert!(result.is_ok());
        let received_block = shares_rx
            .recv()
            .await
            .expect("Failed to receive compact block");
        assert!(received_block.compact_block.header == block.header);
    }
}
