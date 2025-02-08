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

use bitcoin::Transaction;
use bitcoin::TxMerkleNode;

pub mod coinbase;

pub fn compute_merkle_root(transactions: &[Transaction]) -> Option<TxMerkleNode> {
    match bitcoin::merkle_tree::calculate_root(transactions.iter().map(Transaction::compute_txid)) {
        Some(root) => Some(root.into()),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::transactions::coinbase::create_coinbase_transaction;
    use bitcoin::Network;
    use bitcoin::PublicKey;
    use bitcoin::Transaction;

    #[test]
    fn test_compute_merkle_root() {
        let transactions = vec![];
        let merkle_root = compute_merkle_root(&transactions);
        assert!(merkle_root.is_none());
    }

    #[test]
    fn test_compute_merkle_root_with_one_transaction() {
        let pubkey = "020202020202020202020202020202020202020202020202020202020202020202"
            .parse::<PublicKey>()
            .unwrap();

        let coinbase_tx = create_coinbase_transaction(&pubkey, Network::Regtest);
        let transactions = vec![coinbase_tx];
        let merkle_root = compute_merkle_root(&transactions);
        assert!(merkle_root.is_some());
    }
}
