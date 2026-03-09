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

use bitcoin::{Address, Transaction, TxOut};

const SHARE_VALUE: u64 = 1; // 100_000_000 satoshi == 1 BTC == 1 share

/// Create a coinbase transaction for the given bitcoin address and amount.
/// For now, all shares are equal value, so the amount is 1 unit share coin.
pub fn create_coinbase_transaction(btcaddress: &Address) -> Transaction {
    let script_pubkey = btcaddress.script_pubkey();

    // Create TxOut with script_pubkey and amount of 1 satoshi
    let tx_out = TxOut {
        value: bitcoin::Amount::from_int_btc(SHARE_VALUE),
        script_pubkey,
    };

    // Create input with null outpoint and empty script sig
    let tx_in = bitcoin::TxIn {
        previous_output: bitcoin::OutPoint::null(),
        script_sig: bitcoin::ScriptBuf::new(),
        sequence: bitcoin::Sequence::MAX,
        witness: bitcoin::Witness::new(),
    };

    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{CompressedPublicKey, Network};

    #[test]
    fn test_create_share_block_coinbase_transaction() {
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<CompressedPublicKey>()
            .unwrap();
        let address = Address::p2wpkh(&pubkey, Network::Regtest);

        let transaction = create_coinbase_transaction(&address);

        assert_eq!(transaction.version, bitcoin::transaction::Version::TWO);
        assert_eq!(transaction.lock_time, bitcoin::absolute::LockTime::ZERO);
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.output.len(), 1);

        assert!(transaction.is_coinbase());

        let output = &transaction.output[0];
        assert_eq!(output.value, bitcoin::Amount::from_int_btc(SHARE_VALUE));

        assert_eq!(output.script_pubkey, address.script_pubkey());
    }
}
