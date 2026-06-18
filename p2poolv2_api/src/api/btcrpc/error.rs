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

use bitcoindrpc::BitcoindRpcError;
use serde::Serialize;

// Standard JSON-RPC / Bitcoin Core error codes used at the proxy layer.
// Upstream bitcoind codes (e.g. -5, -8, -25) are passed through verbatim.
pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;

#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

/// Map a BitcoindRpcError to an RpcError suitable for the proxy response.
/// Upstream RPC errors preserve their original code and message verbatim so
/// that clients keyed on Bitcoin Core error codes (-5, -8, -25, -26, -27)
/// continue to work correctly.
pub fn bitcoind_error_to_rpc_error(e: BitcoindRpcError) -> RpcError {
    match e {
        BitcoindRpcError::RpcError { code, message } => RpcError { code, message },
        BitcoindRpcError::HttpError {
            status_code,
            message,
        } => RpcError {
            code: INTERNAL_ERROR,
            message: format!("HTTP error {status_code}: {message}"),
        },
        BitcoindRpcError::ParseError { message } => RpcError {
            code: PARSE_ERROR,
            message,
        },
        BitcoindRpcError::Other(msg) => RpcError {
            code: INTERNAL_ERROR,
            message: msg,
        },
    }
}
