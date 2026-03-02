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

use bitcoin::Transaction;
use bitcoin::consensus::{Decodable, Encodable};
use std::ops::{Deref, DerefMut};

/// A transaction on the share chain.
///
/// Wraps a bitcoin::Transaction to provide type safety, distinguishing
/// share chain transactions from bitcoin block transactions.
///
/// Deref and encoding traits are implemented to support easier access
/// to Transaction methods and serde
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShareTransaction(pub Transaction);

impl Deref for ShareTransaction {
    type Target = Transaction;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ShareTransaction {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Encodable for ShareTransaction {
    #[inline]
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ShareTransaction {
    #[inline]
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Ok(ShareTransaction(Transaction::consensus_decode(r)?))
    }
}
