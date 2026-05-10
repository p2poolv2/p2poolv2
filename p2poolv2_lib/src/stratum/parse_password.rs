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

//! Parse stratum password field for difficulty and hashrate hints.
//!
//! Miners can specify start difficulty via the password field in mining.authorize:
//! - `d=<integer>` sets the difficulty directly
//! - `th=<integer>` specifies terahash/s, converted to difficulty
//!
//! If both are present, `d=` takes priority.
//!
//! We manually parse d= and th= key value pairs. If we add more params we can switch
//! to regex when needed.

use crate::stratum::difficulty_adjuster::TARGET_DRR;

/// Result of parsing the password field for difficulty hints.
pub struct ParsedPassword {
    pub difficulty: Option<u64>,
}

/// Parse the password string for `d=<integer>` and `th=<integer>` options.
///
/// Scans the password for recognized options anywhere in the string,
/// separated by commas, spaces, or at string boundaries.
/// `d=` (explicit difficulty) takes priority over `th=` (terahash/s).
/// Returns `ParsedPassword { difficulty: None }` if no valid option is found.
pub fn parse_password(password: &str) -> ParsedPassword {
    let difficulty_value = extract_value(password, "d=");
    if let Some(value) = difficulty_value {
        if value > 0 {
            return ParsedPassword {
                difficulty: Some(value),
            };
        }
    }

    let terahash_value = extract_value(password, "th=");
    if let Some(value) = terahash_value {
        if value > 0 {
            let difficulty = terahash_to_difficulty(value);
            if difficulty > 0 {
                return ParsedPassword {
                    difficulty: Some(difficulty),
                };
            }
        }
    }

    ParsedPassword { difficulty: None }
}

/// Extract an integer value for a given key (e.g., "d=" or "th=") from the password string.
///
/// The key can appear at the start of the string, or after a comma or space.
/// The value is the sequence of digits immediately following the key.
fn extract_value(password: &str, key: &str) -> Option<u64> {
    let password_lower_case = password.to_lowercase();
    let mut search_from = 0;

    while search_from < password_lower_case.len() {
        let position = match password_lower_case[search_from..].find(key) {
            Some(pos) => search_from + pos,
            None => return None,
        };

        let at_valid_boundary = position == 0
            || matches!(
                password_lower_case.as_bytes()[position - 1],
                b',' | b' ' | b'\t' | b';'
            );

        if at_valid_boundary {
            let digits_start = position + key.len();
            let digits: String = password_lower_case[digits_start..]
                .chars()
                .take_while(|character| character.is_ascii_digit())
                .collect();

            if !digits.is_empty() {
                return digits.parse::<u64>().ok();
            }
        }

        search_from = position + key.len();
    }

    None
}

/// Convert terahash/s to difficulty.
///
/// Uses the formula: difficulty = hashrate_hps / (TARGET_DRR * 2^32)
/// where hashrate_hps = terahash * 10^12
///
/// Note that 1/TARGET_DRR gives us target share rate.
fn terahash_to_difficulty(terahash: u64) -> u64 {
    let hashrate_hps = terahash as f64 * 1e12;
    let difficulty = hashrate_hps / (TARGET_DRR * 4_294_967_296.0);
    difficulty as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_difficulty_direct() {
        let result = parse_password("d=1000");
        assert_eq!(result.difficulty, Some(1000));
    }

    #[test]
    fn test_parse_difficulty_large_value() {
        let result = parse_password("d=999999");
        assert_eq!(result.difficulty, Some(999999));
    }

    #[test]
    fn test_parse_terahash() {
        let result = parse_password("th=1");
        // 1 TH/s = 10^12 / (0.3 * 2^32) = 776
        assert_eq!(result.difficulty, Some(776));
    }

    #[test]
    fn test_parse_terahash_large() {
        let result = parse_password("th=100");
        let expected = terahash_to_difficulty(100);
        assert_eq!(result.difficulty, Some(expected));
    }

    #[test]
    fn test_difficulty_takes_priority_over_terahash() {
        let result = parse_password("d=500,th=100");
        assert_eq!(result.difficulty, Some(500));
    }

    #[test]
    fn test_difficulty_in_middle_of_string() {
        let result = parse_password("someprefix,d=200,somesuffix");
        assert_eq!(result.difficulty, Some(200));
    }

    #[test]
    fn test_terahash_in_middle_of_string() {
        let result = parse_password("x,th=10,y");
        let expected = terahash_to_difficulty(10);
        assert_eq!(result.difficulty, Some(expected));
    }

    #[test]
    fn test_empty_string_returns_none() {
        let result = parse_password("");
        assert_eq!(result.difficulty, None);
    }

    #[test]
    fn test_no_recognized_option_returns_none() {
        let result = parse_password("x");
        assert_eq!(result.difficulty, None);
    }

    #[test]
    fn test_plain_password_returns_none() {
        let result = parse_password("mypassword123");
        assert_eq!(result.difficulty, None);
    }

    #[test]
    fn test_difficulty_zero_returns_none() {
        let result = parse_password("d=0");
        assert_eq!(result.difficulty, None);
    }

    #[test]
    fn test_terahash_zero_returns_none() {
        let result = parse_password("th=0");
        assert_eq!(result.difficulty, None);
    }

    #[test]
    fn test_case_insensitive_difficulty() {
        let result = parse_password("D=500");
        assert_eq!(result.difficulty, Some(500));
    }

    #[test]
    fn test_case_insensitive_terahash() {
        let result = parse_password("TH=1");
        assert_eq!(result.difficulty, Some(776));
    }

    #[test]
    fn test_space_separated_options() {
        let result = parse_password("password d=300");
        assert_eq!(result.difficulty, Some(300));
    }

    #[test]
    fn test_does_not_match_inside_word() {
        let result = parse_password("method=123");
        assert_eq!(result.difficulty, None);
    }

    #[test]
    fn test_terahash_to_difficulty_conversion() {
        // difficulty = th * 10^12 / (TARGET_DRR * 2^32)
        let divisor = TARGET_DRR * 4_294_967_296.0;

        let diff_1th = (1e12 / divisor) as u64;
        assert_eq!(terahash_to_difficulty(1), diff_1th);

        let diff_10th = (10e12 / divisor) as u64;
        assert_eq!(terahash_to_difficulty(10), diff_10th);

        let diff_1000th = (1000e12 / divisor) as u64;
        assert_eq!(terahash_to_difficulty(1000), diff_1000th);
    }
}
