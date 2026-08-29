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

//! Parse stratum password field for difficulty hints and the miner share address.
//!
//! Miners can specify options via the password field in mining.authorize:
//! - `d=<integer>` sets the difficulty directly
//! - `th=<integer>` specifies terahash/s, converted to difficulty
//! - `p2p=<miner share address>` names the owner of the miner's share coinbase outputs
//!
//! If both `d=` and `th=` are present, `d=` takes priority.
//!
//! This module only extracts values. Policy lives with the caller: difficulty
//! clamping and the share address network check both happen at authorize.
//!
//! We manually parse the key value pairs. If we add more params we can switch
//! to regex when needed.

use crate::address::{Address, AddressError};
use crate::stratum::difficulty_adjuster::TARGET_DRR;
use std::str::FromStr;

/// Result of parsing the password field.
pub struct ParsedPassword {
    /// The optional difficulty supplied by a miner connecting to node's stratum
    /// server.
    pub difficulty: Option<u64>,

    /// The share chain address from `p2p=`, in three distinguishable states:
    /// `None` when the key is absent, `Some(Err)` when it was supplied but
    /// unparseable, and `Some(Ok)` when it is a well formed address.
    ///
    /// The distinction matters because authorize rejects a P2Poolv2 mode miner
    /// without an address, and telling someone who typoed their address that
    /// they supplied none would send them looking in the wrong place.
    pub miner_address: Option<Result<Address, AddressError>>,
}

/// Parse the password string for `d=`, `th=` and `p2p=` options.
///
/// Scans the password for recognized options anywhere in the string,
/// separated by commas, spaces, or at string boundaries.
/// `d=` (explicit difficulty) takes priority over `th=` (terahash/s).
pub fn parse_password(password: &str) -> ParsedPassword {
    ParsedPassword {
        difficulty: parse_difficulty(password),
        miner_address: extract_string_value(password, "p2p=").map(Address::from_str),
    }
}

/// Resolve the session start difficulty from `d=`, falling back to `th=`.
fn parse_difficulty(password: &str) -> Option<u64> {
    let difficulty_value = extract_value(password, "d=");
    if let Some(value) = difficulty_value
        && value > 0
    {
        return Some(value);
    }

    let terahash_value = extract_value(password, "th=");
    if let Some(value) = terahash_value
        && value > 0
    {
        let difficulty = terahash_to_difficulty(value);
        if difficulty > 0 {
            return Some(difficulty);
        }
    }

    None
}

/// Extract a string value for a given key (e.g. "p2p=") from the password.
///
/// Follows the same boundary rules as [`extract_value`]: the key may appear at
/// the start of the string or after a comma, space, tab or semicolon. The value
/// runs to the next such delimiter or to the end of the string.
///
/// Unlike [`extract_value`] this matches the key case insensitively against the
/// original string rather than scanning a lowercased copy, and returns a slice
/// of the original. Lowercasing first would silently repair a mixed case bech32
/// address, which BIP173 requires be rejected because mixed case defeats the
/// checksum, and `str::to_lowercase` can change byte length on non-ASCII input
/// and desynchronise the offsets.
fn extract_string_value<'a>(password: &'a str, key: &str) -> Option<&'a str> {
    let bytes = password.as_bytes();
    let key_bytes = key.as_bytes();
    if key_bytes.is_empty() || bytes.len() < key_bytes.len() {
        return None;
    }

    for position in 0..=bytes.len() - key_bytes.len() {
        if !bytes[position..position + key_bytes.len()].eq_ignore_ascii_case(key_bytes) {
            continue;
        }

        let at_valid_boundary =
            position == 0 || matches!(bytes[position - 1], b',' | b' ' | b'\t' | b';');
        if !at_valid_boundary {
            continue;
        }

        let value_start = position + key_bytes.len();
        let value_end = bytes[value_start..]
            .iter()
            .position(|byte| matches!(byte, b',' | b' ' | b'\t' | b';'))
            .map_or(bytes.len(), |offset| value_start + offset);

        if value_end > value_start {
            return Some(&password[value_start..value_end]);
        }
    }

    None
}

/// Extract an integer value for a given key (e.g., "d=" or "th=") from the password string.
///
/// The key can appear at the start of the string, or after a comma or space.
/// The value is the sequence of digits immediately following the key.
fn extract_value(password: &str, key: &str) -> Option<u64> {
    let password_lower_case = password.to_lowercase();
    let mut search_from = 0;

    while search_from < password_lower_case.len() {
        let position = {
            let pos = password_lower_case[search_from..].find(key)?;
            search_from + pos
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

#[cfg(test)]
mod p2p_address_tests {
    use super::*;
    use bitcoin::Network;

    /// BIP086 tweak of PUBKEY_G, the same value the fixtures use.
    const SHARE_ADDRESS: &str =
        "tp2pool1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sss3v29v";

    #[test]
    fn absent_key_yields_none() {
        assert!(parse_password("d=1000").miner_address.is_none());
    }

    #[test]
    fn empty_password_yields_none() {
        assert!(parse_password("").miner_address.is_none());
    }

    #[test]
    fn address_alone_is_parsed() {
        let parsed = parse_password(&format!("p2p={SHARE_ADDRESS}"));
        let address = parsed.miner_address.unwrap().unwrap();
        assert_eq!(address.to_string(), SHARE_ADDRESS);
        assert_eq!(address.network(), Network::Testnet4);
    }

    #[test]
    fn address_after_difficulty_is_parsed() {
        let parsed = parse_password(&format!("d=1000,p2p={SHARE_ADDRESS}"));
        assert_eq!(parsed.difficulty, Some(1000));
        assert_eq!(
            parsed.miner_address.unwrap().unwrap().to_string(),
            SHARE_ADDRESS
        );
    }

    #[test]
    fn address_before_difficulty_is_parsed() {
        let parsed = parse_password(&format!("p2p={SHARE_ADDRESS},d=1000"));
        assert_eq!(parsed.difficulty, Some(1000));
        assert_eq!(
            parsed.miner_address.unwrap().unwrap().to_string(),
            SHARE_ADDRESS
        );
    }

    #[test]
    fn address_is_parsed_alongside_terahash() {
        let parsed = parse_password(&format!("th=100 p2p={SHARE_ADDRESS}"));
        assert!(parsed.difficulty.is_some());
        assert_eq!(
            parsed.miner_address.unwrap().unwrap().to_string(),
            SHARE_ADDRESS
        );
    }

    #[test]
    fn semicolon_separates_the_address_from_a_later_option() {
        let parsed = parse_password(&format!("p2p={SHARE_ADDRESS};d=1000"));
        assert_eq!(parsed.difficulty, Some(1000));
        assert_eq!(
            parsed.miner_address.unwrap().unwrap().to_string(),
            SHARE_ADDRESS
        );
    }

    /// The key is matched case insensitively, like `d=` and `th=`.
    #[test]
    fn key_is_matched_case_insensitively() {
        let parsed = parse_password(&format!("P2P={SHARE_ADDRESS}"));
        assert_eq!(
            parsed.miner_address.unwrap().unwrap().to_string(),
            SHARE_ADDRESS
        );
    }

    /// A malformed address must be distinguishable from an absent one, so that
    /// authorize can tell a miner who typoed from one who supplied nothing.
    #[test]
    fn malformed_address_is_some_err_not_none() {
        let parsed = parse_password("p2p=not-an-address");
        assert!(parsed.miner_address.unwrap().is_err());
    }

    #[test]
    fn bitcoin_address_in_p2p_is_some_err() {
        let parsed = parse_password("p2p=tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
        assert!(parsed.miner_address.unwrap().is_err());
    }

    /// Mixed case must survive extraction unrepaired so the address parser can
    /// reject it. Lowercasing the password first would silently accept it and
    /// defeat the bech32 checksum guarantee.
    #[test]
    fn mixed_case_address_reaches_the_parser_and_is_rejected() {
        let mixed_case = format!("p2p=Tp2pool{}", &SHARE_ADDRESS[7..]);
        let parsed = parse_password(&mixed_case);
        assert!(parsed.miner_address.unwrap().is_err());
    }

    /// An uppercase address is valid bech32 and must round trip to the same
    /// address, which only works because extraction preserves the original case.
    #[test]
    fn uppercase_address_is_accepted() {
        let parsed = parse_password(&format!("p2p={}", SHARE_ADDRESS.to_uppercase()));
        assert_eq!(
            parsed.miner_address.unwrap().unwrap().to_string(),
            SHARE_ADDRESS
        );
    }

    /// `p2p=` must not match inside another token, matching the boundary rule
    /// that `extract_value` already applies to `d=` and `th=`.
    #[test]
    fn key_embedded_in_another_token_is_ignored() {
        let parsed = parse_password(&format!("xp2p={SHARE_ADDRESS}"));
        assert!(parsed.miner_address.is_none());
    }

    #[test]
    fn empty_value_yields_none() {
        assert!(parse_password("p2p=").miner_address.is_none());
    }

    /// `p2p=<address>` is 71 characters, which is long for a stratum password
    /// field and some miner firmware imposes its own input limit. The bech32
    /// checksum is what makes that safe: a truncated address fails loudly
    /// instead of silently resolving to a different valid one. This pins that,
    /// because silent truncation would pay shares to the wrong owner.
    #[test]
    fn truncated_address_is_rejected_rather_than_silently_accepted() {
        let truncated = &SHARE_ADDRESS[..SHARE_ADDRESS.len() - 1];
        let parsed = parse_password(&format!("p2p={truncated}"));
        assert!(parsed.miner_address.unwrap().is_err());
    }

    #[test]
    fn heavily_truncated_address_is_rejected() {
        let truncated = &SHARE_ADDRESS[..SHARE_ADDRESS.len() - 8];
        let parsed = parse_password(&format!("p2p={truncated}"));
        assert!(parsed.miner_address.unwrap().is_err());
    }

    #[test]
    fn empty_value_followed_by_another_option_yields_none() {
        let parsed = parse_password("p2p=,d=1000");
        assert!(parsed.miner_address.is_none());
        assert_eq!(parsed.difficulty, Some(1000));
    }
}
