// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

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
