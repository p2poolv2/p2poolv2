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

use std::fmt::{Display, Formatter, Result};

/// Error types for the Stratum server used to propagate internal errors
/// and eventually disconnect misbehaving miners. Not sent to miners on the wire.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid stratum method: {0}")]
    InvalidMethod(String),
    #[error("Invalid parameters provided: {0}")]
    InvalidParams(String),
    #[error("Authorization failed: {0}")]
    AuthorizationFailure(String),
    #[error("Submit failure: {0}")]
    SubmitFailure(String),
    #[error("Subscription failure: {0}")]
    SubscriptionFailure(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Timeout Error")]
    TimeoutError,
}

/// Stratum V1 JSON-RPC error codes sent to miners.
///
/// Share submission codes -9..5 follow ckpool's `share_err` enum
/// (libckpool.h:340-355). Protocol codes 20-25 follow the blitzpool
/// convention (eStratumErrorCode.ts). Negative codes -32700..-32600
/// follow JSON-RPC 2.0.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StratumErrorCode {
    /// Invalid nonce2 hex length
    InvalidNonce2 = -9,
    /// Worker name does not match session
    WorkerMismatch = -8,
    /// Missing nonce parameter
    NoNonce = -7,
    /// Missing ntime parameter
    NoNtime = -6,
    /// Missing nonce2 parameter
    NoNonce2 = -5,
    /// Missing job_id parameter
    NoJobId = -4,
    /// Missing username parameter
    NoUsername = -3,
    /// Submit params array too short
    InvalidSize = -2,
    /// Params is not a JSON array
    NotArray = -1,
    /// Unknown or expired job ID
    InvalidJobId = 1,
    /// Share submitted against a retired job
    Stale = 2,
    /// ntime out of allowed range
    NtimeOutOfRange = 3,
    /// Duplicate share submission
    Duplicate = 4,
    /// Share hash above pool target (below pool difficulty)
    AboveTarget = 5,
    /// Catch-all unknown error
    OtherUnknown = 20,
    /// Worker not authorized
    UnauthorizedWorker = 24,
    /// Must subscribe before submitting shares
    NotSubscribed = 25,
    /// Invalid JSON cannot be parsed
    ParseError = -32700,
    /// Unknown method name
    MethodNotFound = -32601,
    /// Invalid method parameters
    InvalidParams = -32602,
}

impl Display for StratumErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self {
            Self::InvalidNonce2 => "Invalid nonce2 length",
            Self::WorkerMismatch => "Worker mismatch",
            Self::NoNonce => "No nonce",
            Self::NoNtime => "No ntime",
            Self::NoNonce2 => "No nonce2",
            Self::NoJobId => "No job_id",
            Self::NoUsername => "No username",
            Self::InvalidSize => "Invalid array size",
            Self::NotArray => "Params not array",
            Self::InvalidJobId => "Invalid JobID",
            Self::Stale => "Stale",
            Self::NtimeOutOfRange => "Ntime out of range",
            Self::Duplicate => "Duplicate",
            Self::AboveTarget => "Above target",
            Self::OtherUnknown => "Unknown error",
            Self::UnauthorizedWorker => "Unauthorized worker",
            Self::NotSubscribed => "Not subscribed",
            Self::ParseError => "Parse error",
            Self::MethodNotFound => "Method not found",
            Self::InvalidParams => "Invalid params",
        };
        f.write_str(msg)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn test_error_display() {
        assert_eq!(
            Error::InvalidMethod("foo".into()).to_string(),
            "Invalid stratum method: foo"
        );
        assert_eq!(
            Error::InvalidParams("bar".into()).to_string(),
            "Invalid parameters provided: bar"
        );
        assert_eq!(
            Error::AuthorizationFailure("denied".into()).to_string(),
            "Authorization failed: denied"
        );
        assert_eq!(Error::TimeoutError.to_string(), "Timeout Error");
    }

    #[test]
    fn test_error_code_values() {
        assert_eq!(StratumErrorCode::Duplicate as i32, 4);
        assert_eq!(StratumErrorCode::AboveTarget as i32, 5);
        assert_eq!(StratumErrorCode::Stale as i32, 2);
        assert_eq!(StratumErrorCode::InvalidJobId as i32, 1);
        assert_eq!(StratumErrorCode::UnauthorizedWorker as i32, 24);
        assert_eq!(StratumErrorCode::NotSubscribed as i32, 25);
        assert_eq!(StratumErrorCode::ParseError as i32, -32700);
        assert_eq!(StratumErrorCode::OtherUnknown as i32, 20);
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(StratumErrorCode::Duplicate.to_string(), "Duplicate");
        assert_eq!(StratumErrorCode::AboveTarget.to_string(), "Above target");
        assert_eq!(StratumErrorCode::Stale.to_string(), "Stale");
        assert_eq!(StratumErrorCode::InvalidJobId.to_string(), "Invalid JobID");
        assert_eq!(
            StratumErrorCode::UnauthorizedWorker.to_string(),
            "Unauthorized worker"
        );
        assert_eq!(
            StratumErrorCode::NotSubscribed.to_string(),
            "Not subscribed"
        );
        assert_eq!(StratumErrorCode::ParseError.to_string(), "Parse error");
        assert_eq!(StratumErrorCode::OtherUnknown.to_string(), "Unknown error");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::other("test");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::IoError(_)));
        assert_eq!(err.to_string(), "IO error: test");
    }
}
