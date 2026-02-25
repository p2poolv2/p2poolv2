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

pub mod chain_info;
pub mod pplns_shares;
pub mod share_lookup;
pub mod shares_info;

// Re-export the shared store functionality
pub mod store {
    use crate::store::{Store, writer::StoreError};

    /// Open a store from the given path
    pub fn open_store(store_path: String) -> Result<Store, StoreError> {
        tracing::debug!("Opening store in read-only mode: {:?}", store_path);

        Store::new(store_path, true).map_err(|e| {
            tracing::error!("Failed to open store: {}", e);
            e
        })
    }
}
