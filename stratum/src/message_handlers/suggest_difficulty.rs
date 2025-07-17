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

use crate::difficulty_adjuster::DifficultyAdjusterTrait;
use crate::error::Error;
use crate::messages::{Message, Request, SetDifficultyNotification};
use crate::session::Session;
use tracing::debug;

pub async fn handle_suggest_difficulty<'a, D: DifficultyAdjusterTrait>(
    message: Request<'a>,
    session: &mut Session<D>,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.suggest_difficulty message");

    match message.params.first() {
        Some(param) => {
            if let Ok(suggested_difficulty) = param.parse::<u64>() {
                session.suggested_difficulty = Some(suggested_difficulty);
                debug!("Suggested difficulty set to {}", suggested_difficulty);
                Ok(vec![Message::SetDifficulty(
                    SetDifficultyNotification::new(suggested_difficulty),
                )])
            } else {
                Err(Error::InvalidParams("Invalid suggested difficulty".into()))
            }
        }
        None => Err(Error::InvalidParams(
            "No suggested difficulty provided".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::difficulty_adjuster::DifficultyAdjuster;
    use crate::messages::{Id, Request};
    use std::borrow::Cow;

    #[tokio::test]
    async fn test_handle_suggest_difficulty_valid_param() {
        let mut session = Session::<DifficultyAdjuster>::new(1, None, 1, 0x1fffe000);
        let request = Request {
            id: Some(Id::Number(1)),
            method: "mining.suggest_difficulty".into(),
            params: Cow::Owned(vec!["1000".into()]),
        };

        let result = handle_suggest_difficulty(request, &mut session).await;

        assert!(result.is_ok());
        let messages = result.unwrap();
        assert_eq!(messages.len(), 1);
        if let Message::SetDifficulty(notification) = &messages[0] {
            assert_eq!(notification.params[0], 1000);
        } else {
            panic!("Expected SetDifficulty message");
        }
        assert_eq!(session.suggested_difficulty, Some(1000));
    }

    #[tokio::test]
    async fn test_handle_suggest_difficulty_invalid_param() {
        let mut session = Session::<DifficultyAdjuster>::new(1, None, 1, 0x1fffe000);
        let request = Request {
            id: Some(Id::Number(1)),
            method: "mining.suggest_difficulty".into(),
            params: Cow::Owned(vec!["invalid".into()]),
        };

        let result = handle_suggest_difficulty(request, &mut session).await;

        assert!(result.is_err());
        assert_eq!(
            format!("{}", result.unwrap_err()),
            "Invalid parameters provided: Invalid suggested difficulty"
        );
        assert_eq!(session.suggested_difficulty, None);
    }

    #[tokio::test]
    async fn test_handle_suggest_difficulty_no_param() {
        let mut session = Session::<DifficultyAdjuster>::new(1, None, 1, 0x1fffe000);
        let request = Request {
            id: Some(Id::Number(1)),
            method: "mining.suggest_difficulty".into(),
            params: Cow::Owned(vec![]),
        };

        let result = handle_suggest_difficulty(request, &mut session).await;

        assert!(result.is_err());
        assert_eq!(
            format!("{}", result.unwrap_err()),
            "Invalid parameters provided: No suggested difficulty provided"
        );
        assert_eq!(session.suggested_difficulty, None);
    }
}
