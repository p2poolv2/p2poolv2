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
/// Codes 20-25 follow the stratum v1 convention from slush
/// https://web.archive.org/web/20240225191319/https://braiins.com/stratum-v1/docs
///
/// Minimal negative codes -32700..-32600 from JSON-RPC 2.0 convention.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StratumErrorCode {
    /// Catch-all unknown error
    OtherUnknown = 20,
    /// Job not found or stale
    JobNotFound = 21,
    /// Duplicate share submission
    DuplicateShare = 22,
    /// Share hash does not meet pool difficulty
    LowDifficultyShare = 23,
    /// Worker not authorized
    UnauthorizedWorker = 24,
    /// Must subscribe before submitting shares
    NotSubscribed = 25,
    /// Invalid JSON cannot be parsed
    ParseError = -32700,
    /// Unknown method name
    MethodNotFound = -32601,
}

impl Display for StratumErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self {
            Self::OtherUnknown => "Other/Unknown",
            Self::JobNotFound => "Job not found",
            Self::DuplicateShare => "Duplicate share",
            Self::LowDifficultyShare => "Low difficulty share",
            Self::UnauthorizedWorker => "Unauthorized worker",
            Self::NotSubscribed => "Not subscribed",
            Self::ParseError => "Parse error",
            Self::MethodNotFound => "Method not found",
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
        assert_eq!(StratumErrorCode::OtherUnknown as i32, 20);
        assert_eq!(StratumErrorCode::JobNotFound as i32, 21);
        assert_eq!(StratumErrorCode::DuplicateShare as i32, 22);
        assert_eq!(StratumErrorCode::LowDifficultyShare as i32, 23);
        assert_eq!(StratumErrorCode::UnauthorizedWorker as i32, 24);
        assert_eq!(StratumErrorCode::NotSubscribed as i32, 25);
        assert_eq!(StratumErrorCode::ParseError as i32, -32700);
        assert_eq!(StratumErrorCode::MethodNotFound as i32, -32601);
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(StratumErrorCode::OtherUnknown.to_string(), "Other/Unknown");
        assert_eq!(StratumErrorCode::JobNotFound.to_string(), "Job not found");
        assert_eq!(
            StratumErrorCode::DuplicateShare.to_string(),
            "Duplicate share"
        );
        assert_eq!(
            StratumErrorCode::LowDifficultyShare.to_string(),
            "Low difficulty share"
        );
        assert_eq!(
            StratumErrorCode::UnauthorizedWorker.to_string(),
            "Unauthorized worker"
        );
        assert_eq!(
            StratumErrorCode::NotSubscribed.to_string(),
            "Not subscribed"
        );
        assert_eq!(StratumErrorCode::ParseError.to_string(), "Parse error");
        assert_eq!(
            StratumErrorCode::MethodNotFound.to_string(),
            "Method not found"
        );
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::other("test");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::IoError(_)));
        assert_eq!(err.to_string(), "IO error: test");
    }
}
