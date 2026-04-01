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

pub mod chain;
pub(crate) mod coinbaseaux_flags;
pub(crate) mod compact_block;
pub(crate) mod extranonce;
pub mod genesis;
pub mod handle_stratum_share;
pub mod share_block;
pub mod share_commitment;
pub mod transactions;
pub mod validation;
pub(crate) mod witness_commitment;

/// Serde helpers for `bitcoin::Address` fields.
///
/// `Address<NetworkChecked>` does not implement `Deserialize`, so we
/// round-trip through its string representation.
pub(crate) mod address_serde {
    use bitcoin::Address;

    pub fn serialize<S: serde::Serializer>(
        address: &Address,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&address.to_string())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Address, D::Error> {
        let addr_str: String = serde::Deserialize::deserialize(deserializer)?;
        addr_str
            .parse::<Address<_>>()
            .map(|a| a.assume_checked())
            .map_err(serde::de::Error::custom)
    }
}

/// Serde helpers for `Option<bitcoin::Address>` fields.
pub(crate) mod option_address_serde {
    use bitcoin::Address;

    pub fn serialize<S: serde::Serializer>(
        address: &Option<Address>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match address {
            Some(addr) => serializer.serialize_some(&addr.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Address>, D::Error> {
        let opt: Option<String> = serde::Deserialize::deserialize(deserializer)?;
        match opt {
            Some(addr_str) => addr_str
                .parse::<Address<_>>()
                .map(|a| Some(a.assume_checked()))
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
