// Copyright (C) 2024 [Kulpreet Singh]
//
//  This file is part of P2Poolv2
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
    pub workinfoid: u64,
    pub clientid: u64,
    pub enonce1: &'static str,
    pub nonce2: &'static str,
    pub nonce: &'static str,
    pub ntime: u32,
    pub diff: Decimal,
    pub sdiff: Decimal,
    pub bitcoin_blockhash: &'static str,
}

const SIGNET_GENESIS_DATA: GenesisData = GenesisData {
    workinfoid: 0,
    clientid: 0,
    enonce1: "fdf8b667",
    nonce2: "0000000000000000",
    nonce: "f15f1590",
    ntime: 1740044600, // u32::from_str_radix("67b6f938", 16).unwrap(),
    diff: dec!(1.0),
    sdiff: dec!(31.465847594928551),
    bitcoin_blockhash: "000000000822bbfaf34d53fc43d0c1382054d3aafe31893020c315db8b0a19f9",
};

const TESTNET4_GENESIS_DATA: GenesisData = GenesisData {
    workinfoid: 0,
    clientid: 0,
    enonce1: "771de467",
    nonce2: "0000000000000000",
    nonce: "74927904",
    ntime: 1743003095, // u32::from_str_radix("67b6f938", 16).unwrap(),
    diff: dec!(1.0),
    sdiff: dec!(4.0170006421734943),
    bitcoin_blockhash: "000000003fba69400bbc385acd52b07dbe7779ea5f8995dd4aadf4a86b74cc55",
};

/// Get the genesis data for a given network
pub fn genesis_data(network: bitcoin::Network) -> Result<GenesisData, Box<dyn Error>> {
    match network {
        bitcoin::Network::Signet => Ok(SIGNET_GENESIS_DATA),
        bitcoin::Network::Testnet4 => Ok(TESTNET4_GENESIS_DATA),
        _ => Err("Unsupported network".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signet_genesis_data() {
        let genesis = genesis_data(bitcoin::Network::Signet).unwrap();
        assert_eq!(genesis.workinfoid, 0);
        assert_eq!(genesis.clientid, 0);
        assert_eq!(genesis.enonce1, "fdf8b667");
        assert_eq!(genesis.nonce2, "0000000000000000");
        assert_eq!(genesis.nonce, "f15f1590");
        assert_eq!(genesis.ntime, 1740044600);
        assert_eq!(genesis.diff, dec!(1.0));
        assert_eq!(genesis.sdiff, dec!(31.465847594928551));
        assert_eq!(
            genesis.bitcoin_blockhash,
            "000000000822bbfaf34d53fc43d0c1382054d3aafe31893020c315db8b0a19f9"
        );
    }

    #[test]
    fn test_testnet4_genesis_data() {
        let genesis = genesis_data(bitcoin::Network::Testnet4).unwrap();
        assert_eq!(genesis.workinfoid, 0);
        assert_eq!(genesis.clientid, 0);
        assert_eq!(genesis.enonce1, "771de467");
        assert_eq!(genesis.nonce2, "0000000000000000");
        assert_eq!(genesis.nonce, "74927904");
        assert_eq!(genesis.ntime, 1743003095);
        assert_eq!(genesis.diff, dec!(1.0));
        assert_eq!(genesis.sdiff, dec!(4.0170006421734943));
        assert_eq!(
            genesis.bitcoin_blockhash,
            "000000003fba69400bbc385acd52b07dbe7779ea5f8995dd4aadf4a86b74cc55"
        );
    }
}
