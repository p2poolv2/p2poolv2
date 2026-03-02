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

use bitcoin::absolute::Time;
use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize_time<S>(time: &Time, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert Time to hex string
    let hex = format!("{:08x}", time.to_consensus_u32());
    serializer.serialize_str(&hex)
}

pub fn deserialize_time<'de, D>(deserializer: D) -> Result<Time, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let time_str: String = String::deserialize(deserializer)?;

    // Parse hex string to u32
    let timestamp = u32::from_str_radix(&time_str, 16)
        .map_err(|e| D::Error::custom(format!("Invalid time format: {e}")))?;

    // Convert to Time
    Time::from_consensus(timestamp).map_err(|e| D::Error::custom(format!("Invalid timestamp: {e}")))
}
