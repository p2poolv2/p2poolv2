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

pub mod accounting;
pub mod auth;
pub mod cli_commands;
pub mod command;
pub mod config;
pub mod logging;
pub mod middleware;
pub mod node;
pub mod service;
pub mod shares;
pub mod store;
pub mod stratum;
pub mod utils;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub use service::build_service;
