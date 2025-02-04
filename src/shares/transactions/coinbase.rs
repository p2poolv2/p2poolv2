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

use bitcoin::{Address, Network, PublicKey, Transaction, TxOut};

const SHARE_VALUE: u64 = 1;

/// Create a P2PKH coinbase transaction for the given public key and amount
/// For now, all shares are equal value, so the amount is 1 unit share coin.
pub fn create_coinbase_transaction(pubkey: &PublicKey, network: Network) -> Transaction {
    // Create P2PKH address from public key
    let address = Address::p2pkh(pubkey, network);

    // Create P2PKH script from address
    let script_pubkey = address.script_pubkey();

    // Create TxOut with script_pubkey and amount of 1 satoshi
    let tx_out = TxOut {
        value: bitcoin::Amount::from_sat(SHARE_VALUE),
        script_pubkey,
    };

    // Create transaction
    let transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![tx_out],
    };

    transaction
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_share_block_coinbase_transaction() {
        // Create a test public key
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<PublicKey>()
            .unwrap();

        // Create coinbase transaction
        let transaction = create_coinbase_transaction(&pubkey, Network::Regtest);

        // Verify transaction properties
        assert_eq!(transaction.version, bitcoin::transaction::Version::TWO);
        assert_eq!(transaction.lock_time, bitcoin::absolute::LockTime::ZERO);
        assert!(transaction.input.is_empty());
        assert_eq!(transaction.output.len(), 1);

        // Verify output properties
        let output = &transaction.output[0];
        assert_eq!(output.value, bitcoin::Amount::from_sat(SHARE_VALUE));

        // Verify output goes to correct address
        let expected_address = Address::p2pkh(&pubkey, Network::Regtest);
        assert_eq!(output.script_pubkey, expected_address.script_pubkey());
    }
}
