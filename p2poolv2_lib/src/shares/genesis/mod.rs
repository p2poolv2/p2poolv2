// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::config::Chain;
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
    timestamp: 1792472400, // 10-20-2026T0500
};

// Testnet5 block at height 35, hash
// 00000000000002bd0196f81f7b58c99cb72b2e4b4720bb24dc98c2a47ae3b3b8,
// from the lapis.erisian.com.au testnet5 bootstrap chain.
const TESTNET5_GENESIS_DATA: GenesisData = GenesisData {
    public_key: "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
    bitcoin_block: include_bytes!("testnet5.dat"),
    bitcoin_height: 35,
    timestamp: 1794634644, // 11-14-2026T0537
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

/// Get the genesis data for a given chain
pub fn genesis_data(chain: Chain) -> Result<GenesisData, Box<dyn Error>> {
    match chain {
        Chain::Signet => Ok(SIGNET_GENESIS_DATA),
        Chain::Testnet4 => Ok(TESTNET4_GENESIS_DATA),
        Chain::Testnet5 => Ok(TESTNET5_GENESIS_DATA),
        Chain::Main => Ok(MAINNET_GENESIS_DATA),
        Chain::Regtest => Ok(REGTEST_GENESIS_DATA),
        Chain::Testnet3 => Err("Unsupported chain".into()),
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
        let genesis = genesis_data(Chain::Signet).unwrap();
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
        let genesis = genesis_data(Chain::Testnet4).unwrap();
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
    fn test_testnet5_genesis_block_hash() {
        let genesis = genesis_data(Chain::Testnet5).unwrap();
        let block = deserialize::<Block>(genesis.bitcoin_block).unwrap();

        assert_eq!(
            block.block_hash(),
            BlockHash::from_str("00000000000002bd0196f81f7b58c99cb72b2e4b4720bb24dc98c2a47ae3b3b8")
                .unwrap()
        );
        assert!(block.check_merkle_root());
        assert_eq!(genesis.bitcoin_height, 35);
    }

    #[test]
    fn test_testnet3_has_no_genesis() {
        assert!(genesis_data(Chain::Testnet3).is_err());
    }

    #[test]
    fn test_mainnet_genesis_block_hash() {
        let genesis = genesis_data(Chain::Main).unwrap();
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
        let genesis = genesis_data(Chain::Regtest).unwrap();
        let block = deserialize::<Block>(genesis.bitcoin_block).unwrap();

        assert_eq!(
            block.block_hash(),
            BlockHash::from_str("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
                .unwrap()
        );
        assert!(block.check_merkle_root());
    }
}
