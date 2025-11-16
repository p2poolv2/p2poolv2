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
    /// The public key of the miner that mined the genesis share
    /// block. Is used to build the coinbase for the share block
    pub public_key: &'static str,
    /// The bitcoin block in hex for the share
    pub bitcoin_block_hex: &'static str,
}

const SIGNET_GENESIS_DATA: GenesisData = GenesisData {
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    // for bitcoin blockhash 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6
    // bitcoin_header_hex: "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad22203",
    bitcoin_block_hex: "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad222030101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
};

const TESTNET4_GENESIS_DATA: GenesisData = GenesisData {
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    // for bitcoin blockhash 000000003fba69400bbc385acd52b07dbe7779ea5f8995dd4aadf4a86b74cc55
    bitcoin_block_hex: "", // TODO - Add this
};

// Using the following JSON data for the genesis block
const MAINNET_GENESIS_DATA: GenesisData = GenesisData {
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    // for header hash 00000000000adb0f8eff963322f447aed003a1861009009b7bcab355bbc8e54d. Mining on previousblockhash 000000000000000000011c80ec9a34567d2c612781b2d7b98c30f689e13c7ad1 height 920526
    // header in hex "00a06f239cf5fe7a514fd6f9e64d77cd2345cf225ee3fe9b75bf00000000000000000000923435bf0a5f91886f7f94ade677752a526dec905eef07d181893faf15113a75b039fb6821eb01173c0137da"
    // we need a new block though
    bitcoin_block_hex: "", // TODO - Add this
};

/// Get the genesis data for a given network
pub fn genesis_data(network: bitcoin::Network) -> Result<GenesisData, Box<dyn Error>> {
    match network {
        bitcoin::Network::Signet => Ok(SIGNET_GENESIS_DATA),
        bitcoin::Network::Testnet4 => Ok(TESTNET4_GENESIS_DATA),
        bitcoin::Network::Bitcoin => Ok(MAINNET_GENESIS_DATA),
        _ => Err("Unsupported network".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signet_genesis_data() {
        let genesis = genesis_data(bitcoin::Network::Signet).unwrap();

        let header = bitcoin::consensus::deserialize::<bitcoin::block::Header>(
            hex::decode(genesis.bitcoin_block_hex).unwrap().as_slice(),
        );

        assert!(header.is_ok());
        let header = header.unwrap();
        assert_eq!(header.prev_blockhash, bitcoin::hashes::Hash::all_zeros());
        assert_eq!(header.version, bitcoin::block::Version::ONE);
    }

    #[test]
    fn test_mainnet_genesis_data() {
        let genesis = genesis_data(bitcoin::Network::Bitcoin).unwrap();

        let header = bitcoin::consensus::deserialize::<bitcoin::block::Header>(
            hex::decode(genesis.bitcoin_block_hex).unwrap().as_slice(),
        );

        assert!(header.is_ok());
        let header = header.unwrap();
        assert_eq!(
            header.prev_blockhash.to_string(),
            "00000000000000000000bf759bfee35e22cf4523cd774de6f9d64f517afef59c" // height 000000000000000000011c80ec9a34567d2c612781b2d7b98c30f689e13c7ad1
        );
        assert_eq!(
            header.version,
            bitcoin::block::Version::from_consensus(594518016)
        );
    }
}
