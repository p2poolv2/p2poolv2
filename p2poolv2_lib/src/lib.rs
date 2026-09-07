// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub mod accounting;
pub use p2poolv2_address as address;
pub mod auth;
pub mod command;
pub use p2poolv2_config as config;
pub mod address_display;
pub mod logging;
pub mod middleware;
pub mod monitoring_events;
pub mod node;
pub mod pool_difficulty;
pub mod service;
pub mod shares;
#[cfg(feature = "sim")]
pub mod sim;
pub mod sim_overrides;
pub mod store;
pub mod stratum;
pub mod utils;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use service::spawn_peer_service;
