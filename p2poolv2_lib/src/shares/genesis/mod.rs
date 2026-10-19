// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
    pub public_key: &'static str,
    /// The consensus serialized bitcoin block for the share, embedded
    /// from a raw `.dat` file, e.g. the output of
    /// `bitcoin-cli getblock <hash> 0 | xxd -r -p`
    pub bitcoin_block: &'static [u8],
    /// Bitcoin header height
    pub bitcoin_height: u64,
    /// Unix timestamp for the genesis share block
    pub timestamp: u32,
}

// Bitcoin signet genesis block (height 0), hash
// 00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6.
const SIGNET_GENESIS_DATA: GenesisData = GenesisData {
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    bitcoin_block: include_bytes!("signet.dat"),
    bitcoin_height: 0,
    timestamp: 1776855600,
};

// Testnet4 block hash 0000000000a57b6dd9b7340a2e2cbb7069a0ccdf28f3db69070ea89d7287444b,
// mined on previousblockhash 0000000000652fb23ade2b38f96257dc2b7d2cb487cc2344cac2d2546e5ceec5.
const TESTNET4_GENESIS_DATA: GenesisData = GenesisData {
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    bitcoin_block: include_bytes!("testnet4.dat"),
    bitcoin_height: 157012,
    timestamp: 1788701400, // 09-06-2026T1330
};

// Mainnet block hash 000000000000000000006fa29653a523d531657ad20d6f946d0fef88c97cd935,
// mined on previousblockhash 00000000000000000001414ee2ca686bd8dc13a40f02d94ff96cb1279dac64aa.
const MAINNET_GENESIS_DATA: GenesisData = GenesisData {
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    bitcoin_block: include_bytes!("main.dat"),
    bitcoin_height: 920527,
    timestamp: 1776855600,
};

// Bitcoin regtest genesis block (height 0), hash
// 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206.
// Used only as a fixed anchor for the share chain on regtest; it does
// not need to match the connected bitcoind's current tip.
const REGTEST_GENESIS_DATA: GenesisData = GenesisData {
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    bitcoin_block: include_bytes!("regtest.dat"),
    bitcoin_height: 0,
    timestamp: 1776855600,
};

/// Get the genesis data for a given network
pub fn genesis_data(network: bitcoin::Network) -> Result<GenesisData, Box<dyn Error>> {
    match network {
        bitcoin::Network::Signet => Ok(SIGNET_GENESIS_DATA),
        bitcoin::Network::Testnet4 => Ok(TESTNET4_GENESIS_DATA),
        bitcoin::Network::Bitcoin => Ok(MAINNET_GENESIS_DATA),
        bitcoin::Network::Regtest => Ok(REGTEST_GENESIS_DATA),
        _ => Err("Unsupported network".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;
    use bitcoin::{Block, BlockHash};
    use std::str::FromStr;

    #[test]
    fn test_signet_genesis_block_hash() {
        let genesis = genesis_data(bitcoin::Network::Signet).unwrap();
        let block = deserialize::<Block>(genesis.bitcoin_block).unwrap();

        assert_eq!(
            block.block_hash(),
            BlockHash::from_str("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6")
                .unwrap()
        );
        assert!(block.check_merkle_root());
    }

    #[test]
    fn test_testnet4_genesis_block_hash() {
        let genesis = genesis_data(bitcoin::Network::Testnet4).unwrap();
        let block = deserialize::<Block>(genesis.bitcoin_block).unwrap();

        assert_eq!(
            block.block_hash(),
            BlockHash::from_str("000000000000000216cf4048741d60335f27012c271df95ce43eb97a79357a40")
                .unwrap()
        );
        assert!(block.check_merkle_root());
        assert_eq!(block.bip34_block_height().unwrap(), genesis.bitcoin_height);
    }

    #[test]
    fn test_mainnet_genesis_block_hash() {
        let genesis = genesis_data(bitcoin::Network::Bitcoin).unwrap();
        let block = deserialize::<Block>(genesis.bitcoin_block).unwrap();

        assert_eq!(
            block.block_hash(),
            BlockHash::from_str("000000000000000000006fa29653a523d531657ad20d6f946d0fef88c97cd935")
                .unwrap()
        );
        assert!(block.check_merkle_root());
    }

    #[test]
    fn test_regtest_genesis_block_hash() {
        let genesis = genesis_data(bitcoin::Network::Regtest).unwrap();
        let block = deserialize::<Block>(genesis.bitcoin_block).unwrap();

        assert_eq!(
            block.block_hash(),
            BlockHash::from_str("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
                .unwrap()
        );
        assert!(block.check_merkle_root());
    }
}
