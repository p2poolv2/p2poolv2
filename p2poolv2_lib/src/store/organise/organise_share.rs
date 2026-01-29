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

use super::Store;
use bitcoin::BlockHash;
use std::error::Error;

impl Store {
    /// Organise a share by updating candidate and confirmed indexes.
    ///
    /// All writes go into the provided `WriteBatch` so the caller can
    /// commit them atomically. Currently a no-op stub; the actual
    /// organisation logic will be implemented later.
    ///
    /// This atomicity is the only reason organise_share is in
    /// Store. We could provide a way to expose WriteBatch, but we'd
    /// still need to find a way to send all updates in a single event
    /// through StoreWriter.
    pub(crate) fn organise_share(
        &self,
        blockhash: &BlockHash,
        _batch: &mut rocksdb::WriteBatch,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        tracing::debug!("organise_share called for {blockhash} (no-op)");
        Ok(())
    }
}
