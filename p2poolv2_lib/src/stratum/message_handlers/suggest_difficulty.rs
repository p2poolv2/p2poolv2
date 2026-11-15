// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::stratum::difficulty_adjuster::DifficultyAdjusterTrait;
use crate::stratum::error::Error;
use crate::stratum::messages::{Message, SetDifficultyNotification, SuggestDifficulty};
use crate::stratum::session::Session;
use tracing::debug;

/// Handle the "mining.suggest_difficulty" message
/// Applies difficulty adjuster's constraints to the suggested difficulty
/// and stores the constrained difficulty to session.
///
/// If the miner already set a difficulty with `d=` or `th=` in the
/// authorize password, the suggestion is recorded but the current
/// difficulty is kept and resent. Firmware often sends a suggestion
/// automatically right after authorize, and it must not override the
/// operator's explicit password setting.
pub async fn handle_suggest_difficulty<'a, D: DifficultyAdjusterTrait>(
    message: SuggestDifficulty<'a>,
    session: &mut Session<D>,
) -> Result<Vec<Message<'a>>, Error> {
    debug!("Handling mining.suggest_difficulty message");

    match message.params.first() {
        Some(param) => {
            let difficulty = session
                .difficulty_adjuster
                .apply_difficulty_constraints(*param, Some(*param));
            session.suggested_difficulty = Some(difficulty);
            let effective_difficulty = if session.difficulty_from_password {
                let current_difficulty = session.difficulty_adjuster.get_current_difficulty();
                debug!(
                    "Ignoring suggested difficulty {} in favour of password difficulty {}",
                    difficulty, current_difficulty
                );
                current_difficulty
            } else {
                session
                    .difficulty_adjuster
                    .set_current_difficulty(difficulty);
                debug!("Suggested difficulty set to {}", difficulty);
                difficulty
            };
            Ok(vec![Message::SetDifficulty(
                SetDifficultyNotification::new(effective_difficulty),
            )])
        }
        None => Err(Error::InvalidParams(
            "No suggested difficulty provided".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use p2poolv2_config::DEFAULT_VERSION_MASK;

    use super::*;
    use crate::stratum::difficulty_adjuster::DifficultyAdjuster;
    use crate::stratum::messages::Id;
    use std::borrow::Cow;

    #[tokio::test]
    async fn test_handle_suggest_difficulty_valid_param() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, None, DEFAULT_VERSION_MASK);
        let request = SuggestDifficulty {
            id: Some(Id::Number(1)),
            method: "mining.suggest_difficulty".into(),
            params: Cow::Owned(vec![1000]),
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
    async fn test_handle_suggest_difficulty_should_respect_pool_max_difficulty() {
        let mut session = Session::<DifficultyAdjuster>::new(1, 1, Some(100), DEFAULT_VERSION_MASK);
        let request = SuggestDifficulty {
            id: Some(Id::Number(1)),
            method: "mining.suggest_difficulty".into(),
            params: Cow::Owned(vec![1000]),
        };

        let result = handle_suggest_difficulty(request, &mut session).await;

        assert!(result.is_ok());
        let messages = result.unwrap();
        assert_eq!(messages.len(), 1);
        if let Message::SetDifficulty(notification) = &messages[0] {
            assert_eq!(notification.params[0], 100);
        } else {
            panic!("Expected SetDifficulty message");
        }
        assert_eq!(session.suggested_difficulty, Some(100));
    }
}
