// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

use std::error::Error;

/// Genesis block data captures the first block in the share chain
///
/// It captures the bitcoin block the work was done, and the work done
/// with certain difficulty.
///
/// This genesis block does _not_ mean the share block met bitcoin
/// difficulty. It just captures where we started from and keeps all
/// nodes build on the same chain.
pub struct GenesisData {
    /// The public key hex string used to derive the miner's bitcoin
    /// address for the genesis share block coinbase
    pub public_key: String,
    /// The bitcoin block in hex for the share
    pub bitcoin_block_hex: String,
    /// Bitcoin header height
    pub bitcoin_height: u64,
    /// Unix timestamp for the genesis share block
    pub timestamp: u32,
}

/// Default miner public key.
pub const DEFAULT_MINER_PK: &str =
    "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d";

/// Get the genesis data for a given network
pub fn genesis_data(network: bitcoin::Network) -> Result<GenesisData, Box<dyn Error>> {
    let (timestamp, bitcoin_height, bitcoin_block_hex) = match network {
        bitcoin::Network::Bitcoin => (1776855600, 0, include_str!("main.rs").into()),
        bitcoin::Network::Signet => (1776855600, 0, include_str!("signet.rs").into()),
        bitcoin::Network::Testnet4 => (1778097600, 130754, include_str!("testnet4.rs").into()),
        bitcoin::Network::Regtest => (1776855600, 0, include_str!("regtest.rs").into()),
        _ => return Err("Unsupported network".into()),
    };

    Ok(GenesisData {
        public_key: DEFAULT_MINER_PK.into(),
        timestamp,
        bitcoin_block_hex,
        bitcoin_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signet_genesis_data() {
        let genesis = genesis_data(bitcoin::Network::Signet).unwrap();

        let block = bitcoin::consensus::deserialize::<bitcoin::Block>(
            hex::decode(genesis.bitcoin_block_hex).unwrap().as_slice(),
        );

        assert!(block.is_ok());
        let header = block.unwrap().header;
        assert_eq!(header.prev_blockhash, bitcoin::hashes::Hash::all_zeros());
        assert_eq!(header.version, bitcoin::block::Version::ONE);
    }
}
