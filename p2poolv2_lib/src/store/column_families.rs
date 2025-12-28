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

/// Column families strings defined in one place for type safety
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColumnFamily {
    Block,
    BlockTxids,
    BitcoinTxids,
    Inputs,
    Outputs,
    Tx,
    BlockIndex,
    BlockHeight,
    Share,
    Job,
    User,
    UserIndex,
    Metadata,
    UnspentOutputs,
}

impl ColumnFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            ColumnFamily::Block => "block",
            ColumnFamily::BlockTxids => "block_txids",
            ColumnFamily::BitcoinTxids => "bitcoin_txids",
            ColumnFamily::Inputs => "inputs",
            ColumnFamily::Outputs => "outputs",
            ColumnFamily::Tx => "tx",
            ColumnFamily::BlockIndex => "block_index",
            ColumnFamily::BlockHeight => "block_height",
            ColumnFamily::Share => "share",
            ColumnFamily::Job => "job",
            ColumnFamily::User => "user",
            ColumnFamily::UserIndex => "user_index",
            ColumnFamily::Metadata => "metadata",
            ColumnFamily::UnspentOutputs => "unspent_outputs",
        }
    }
}

impl std::ops::Deref for ColumnFamily {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ColumnFamily {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<ColumnFamily> for &'static str {
    fn from(val: ColumnFamily) -> Self {
        val.as_str()
    }
}

impl From<ColumnFamily> for String {
    fn from(val: ColumnFamily) -> Self {
        val.as_str().to_string()
    }
}
