// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `p2poolv2_address` crate is a core library module of P2Pool, containing key types like [`address::P2PoolAddress`],
//! network, etc. It is the rough equivalent of the `rust-bitcoin` crate in the BDK stack. The crate name of "address" will
//! be changed in the future.

pub mod address;
pub mod witness_program_codec;
