// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
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

use std::fmt;

/// Error types for the Stratum server used to propagate errors and eventually
/// disconnect misbehaving miners.
#[derive(Debug)]
pub enum Error {
    InvalidMethod(String),
    InvalidParams(String),
    AuthorizationFailure(String),
    SubmitFailure(String),
    SubscriptionFailure(String),
    IoError(std::io::Error),
    InsufficientWork,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMethod(method) => write!(f, "Invalid stratum method: {}", method),
            Self::InvalidParams(msg) => write!(f, "Invalid parameters provided: {}", msg),
            Self::AuthorizationFailure(reason) => write!(f, "Authorization failed: {}", reason),
            Self::SubmitFailure(reason) => write!(f, "Submit failure: {}", reason),
            Self::SubscriptionFailure(reason) => write!(f, "Subscription failure: {}", reason),
            Self::IoError(err) => write!(f, "IO error: {}", err),
            Self::InsufficientWork => write!(f, "Insufficient work"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}
