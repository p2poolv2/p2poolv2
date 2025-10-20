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

use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::error::Error;

/// Genesis block data
pub struct GenesisData {
    pub enonce1: &'static str,
    pub nonce2: &'static str,
    pub nonce: &'static str,
    pub ntime: u32,
    pub diff: Decimal,
    pub bitcoin_blockhash: &'static str,
    pub public_key: &'static str,
    pub bitcoin_block_hex: &'static str,
}

const SIGNET_GENESIS_DATA: GenesisData = GenesisData {
    enonce1: "fdf8b667",
    nonce2: "0000000000000000",
    nonce: "f15f1590",
    ntime: 1740044600, // u32::from_str_radix("67b6f938", 16).unwrap(),
    diff: dec!(1.0),
    bitcoin_blockhash: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    bitcoin_block_hex: "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad222030101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
};

const TESTNET4_GENESIS_DATA: GenesisData = GenesisData {
    enonce1: "771de467",
    nonce2: "0000000000000000",
    nonce: "74927904",
    ntime: 1743003095, // u32::from_str_radix("67b6f938", 16).unwrap(),
    diff: dec!(1.0),
    bitcoin_blockhash: "000000003fba69400bbc385acd52b07dbe7779ea5f8995dd4aadf4a86b74cc55",
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    bitcoin_block_hex: "", // TODO - Add this
};

// Using the following JSON data for the genesis block
// {"Share": {"workinfoid": 7497343058480990096, "clientid": 6, "enonce1": "cee90b68", "nonce2": "2500000000000000", "nonce": "bb4f0152", "ntime": "680cc100", "diff": 600.0, "sdiff": 1288.1044520568391, "hash": "000000000032e088a873de36cfdb61ec3a5e941fc7b7957e18f9c09860a494bd", "result": true, "errn": 0, "createdate": "1745666328,694121232", "createby": "code", "createcode": "parse_submit", "createinet": "0.0.0.0:3333", "workername": "jungly.hydra", "username": "jungly", "address": "212.171.242.161", "agent": "bitaxe/BM1368/v2.5.1"}}
const MAINNET_GENESIS_DATA: GenesisData = GenesisData {
    enonce1: "cee90b68",
    nonce2: "2500000000000000",
    nonce: "bb4f0152",
    ntime: 1740044600, // u32::from_str_radix("67b6f938", 16).unwrap(),
    diff: dec!(600.0), // using a bitaxe client
    bitcoin_blockhash: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
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
        assert_eq!(genesis.enonce1, "fdf8b667");
        assert_eq!(genesis.nonce2, "0000000000000000");
        assert_eq!(genesis.nonce, "f15f1590");
        assert_eq!(genesis.ntime, 1740044600);
        assert_eq!(genesis.diff, dec!(1.0));
        assert_eq!(
            genesis.bitcoin_blockhash,
            "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
        );

        let block = bitcoin::consensus::deserialize::<bitcoin::Block>(
            hex::decode(genesis.bitcoin_block_hex).unwrap().as_slice(),
        );

        assert!(block.is_ok());
        let block = block.unwrap();
        assert_eq!(
            block.header.prev_blockhash,
            bitcoin::hashes::Hash::all_zeros()
        );
        assert_eq!(block.header.version, bitcoin::block::Version::ONE);

        assert_eq!(
            block.header.block_hash().to_string(),
            genesis.bitcoin_blockhash
        );
    }

    #[test]
    fn test_testnet4_genesis_data() {
        let genesis = genesis_data(bitcoin::Network::Testnet4).unwrap();
        assert_eq!(genesis.enonce1, "771de467");
        assert_eq!(genesis.nonce2, "0000000000000000");
        assert_eq!(genesis.nonce, "74927904");
        assert_eq!(genesis.ntime, 1743003095);
        assert_eq!(genesis.diff, dec!(1.0));
        assert_eq!(
            genesis.bitcoin_blockhash,
            "000000003fba69400bbc385acd52b07dbe7779ea5f8995dd4aadf4a86b74cc55"
        );
    }
}
