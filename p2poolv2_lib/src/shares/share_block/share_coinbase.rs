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

use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, Transaction, TxOut, absolute::LockTime,
    transaction::Version,
};
use std::error::Error;

/// Build a coinbase transaction paying out 1.0 in amount to the miner
/// public key
///
/// The coinbase returned is used as the payout mechanism for
/// shares. Each share has exactly 1.0 value from the coinbase.
///
/// Remember that shares expire once they are out of the trading
/// window. https://gist.github.com/pool2win/ba1db237a76d2ebf51829f5a5df6663b
///
/// TODO: Output address should be independent of
pub fn build_share_coinbase(
    miner_pubkey: CompressedPublicKey,
    network: Network,
) -> Result<Transaction, Box<dyn Error>> {
    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::ONE_BTC,
            script_pubkey: Address::p2wpkh(&miner_pubkey, network).into(),
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_pubkey() -> CompressedPublicKey {
        CompressedPublicKey::from_str(
            "020202020202020202020202020202020202020202020202020202020202020202",
        )
        .unwrap()
    }

    #[test]
    fn test_build_share_coinbase_basic_structure() {
        let pubkey = test_pubkey();
        let tx = build_share_coinbase(pubkey, Network::Bitcoin).unwrap();

        assert_eq!(tx.version, Version::TWO);
        assert_eq!(tx.lock_time, LockTime::ZERO);
        assert!(tx.input.is_empty(), "Coinbase should have no inputs");
        assert_eq!(
            tx.output.len(),
            1,
            "Coinbase should have exactly one output"
        );

        assert_eq!(
            tx.output[0].value,
            Amount::ONE_BTC,
            "Output value should be 1 BTC"
        );

        let expected_address = Address::p2wpkh(&pubkey, Network::Bitcoin);
        assert_eq!(
            tx.output[0].script_pubkey,
            expected_address.script_pubkey(),
            "Output script should be p2wpkh for the miner's pubkey"
        );
        assert!(
            tx.output[0].script_pubkey.is_p2wpkh(),
            "Script should be a valid p2wpkh"
        );

        let pubkey2 = CompressedPublicKey::from_str(
            "02ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
        )
        .unwrap();

        let tx = build_share_coinbase(pubkey, Network::Bitcoin).unwrap();
        let tx2 = build_share_coinbase(pubkey2, Network::Bitcoin).unwrap();

        assert_ne!(
            tx.output[0].script_pubkey, tx2.output[0].script_pubkey,
            "Different pubkeys should produce different output scripts"
        );
    }
}
