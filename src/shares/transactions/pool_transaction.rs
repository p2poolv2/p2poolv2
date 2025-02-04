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

use crate::shares::store::Store;
use serde::{Deserialize, Serialize};

/// A transaction in the transaction pool
/// We store this in the database
/// The validated and spent_by fields are cached values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolTransaction {
    pub tx: bitcoin::Transaction,
    pub validated: bool,
    pub spent_by: Option<bitcoin::Txid>,
}

impl PoolTransaction {
    pub fn new(tx: bitcoin::Transaction) -> Self {
        Self {
            tx,
            validated: false,
            spent_by: None,
        }
    }

    // validate the transaction
    pub fn validate(&mut self) {
        self.validated = true;
    }

    // set the spent_by field
    pub fn set_spent_by(&mut self, spent_by: bitcoin::Txid) {
        self.spent_by = Some(spent_by);
    }

    // update the pool transaction in the store by overwriting the existing transaction
    pub fn update(&self, store: &mut Store) {
        store.add_transaction(self.clone()).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_new_pool_transaction() {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let pool_tx = PoolTransaction::new(tx.clone());
        assert_eq!(pool_tx.tx, tx);
        assert!(!pool_tx.validated);
        assert!(pool_tx.spent_by.is_none());
    }

    #[test]
    fn test_validate_transaction() {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let mut pool_tx = PoolTransaction::new(tx);
        assert!(!pool_tx.validated);

        pool_tx.validate();
        assert!(pool_tx.validated);
    }

    #[test]
    fn test_set_spent_by() {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let mut pool_tx = PoolTransaction::new(tx);
        assert!(pool_tx.spent_by.is_none());

        let spent_by = "d2528fc2d7a4f95ace97860f157c895b6098667df0e43912b027cfe58edf304e"
            .parse()
            .unwrap();
        pool_tx.set_spent_by(spent_by);
        assert_eq!(pool_tx.spent_by, Some(spent_by));
    }

    #[test]
    fn test_update_transaction() {
        let temp_dir = tempdir().unwrap();
        let mut store = Store::new(temp_dir.path().to_str().unwrap().to_string());

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version(1),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let mut pool_tx = PoolTransaction::new(tx.clone());
        let txid = tx.compute_txid();

        // Store initial transaction
        store.add_transaction(pool_tx.clone()).unwrap();

        // Modify and update transaction
        pool_tx.validate();
        pool_tx.update(&mut store);

        // Verify updated transaction
        let retrieved_tx = store.get_transaction(&txid).unwrap();
        assert!(retrieved_tx.validated);
    }
}
