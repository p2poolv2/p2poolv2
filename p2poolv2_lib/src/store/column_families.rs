// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Column families strings defined in one place for type safety
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColumnFamily {
    BlockMetadata,
    BlockTxids,
    TxidsBlocks,
    Uncles,
    BitcoinTxids,
    Inputs,
    Outputs,
    Tx,
    BlockIndex,
    BlockHeight,
    Share,
    User,
    UserIndex,
    Metadata,
    SpendsIndex,
    Header,
    TemplateMerkleBranches,
}

impl ColumnFamily {
    pub fn as_str(&self) -> &'static str {
        match self {
            ColumnFamily::BlockMetadata => "block_metadata",
            ColumnFamily::BlockTxids => "block_txids",
            ColumnFamily::TxidsBlocks => "txids_blocks",
            ColumnFamily::Uncles => "uncles",
            ColumnFamily::BitcoinTxids => "bitcoin_txids",
            ColumnFamily::Inputs => "inputs",
            ColumnFamily::Outputs => "outputs",
            ColumnFamily::Tx => "tx",
            ColumnFamily::BlockIndex => "block_index",
            ColumnFamily::BlockHeight => "block_height",
            ColumnFamily::Share => "share",
            ColumnFamily::User => "user",
            ColumnFamily::UserIndex => "user_index",
            ColumnFamily::Metadata => "metadata",
            ColumnFamily::SpendsIndex => "spends_index",
            ColumnFamily::Header => "header",
            ColumnFamily::TemplateMerkleBranches => "template_merkle_branches",
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
