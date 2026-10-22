// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Display formatting. Pure functions, unit tested natively.

const UNITS: [&str; 7] = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];

/// Format a hashrate in hashes per second with an SI unit, e.g. `12.3 TH/s`.
pub fn hashrate(hashes_per_second: f64) -> String {
    if !hashes_per_second.is_finite() || hashes_per_second <= 0.0 {
        return "0 H/s".to_string();
    }
    let mut value = hashes_per_second;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    let decimals = if value >= 100.0 {
        0
    } else if value >= 10.0 {
        1
    } else {
        2
    };
    format!("{value:.decimals$} {}", UNITS[unit])
}

/// Shorten a long hash or address to its head and tail.
pub fn short(text: &str) -> String {
    if text.len() <= 20 {
        return text.to_string();
    }
    format!("{}…{}", &text[..8], &text[text.len() - 8..])
}

/// Relative age of a unix timestamp, e.g. `42s ago`.
pub fn ago(now: u64, then: u64) -> String {
    let seconds = now.saturating_sub(then);
    match seconds {
        0..60 => format!("{seconds}s ago"),
        60..3600 => format!("{}m ago", seconds / 60),
        3600..86_400 => format!("{}h ago", seconds / 3600),
        _ => format!("{}d ago", seconds / 86_400),
    }
}

/// UTC `YYYY-MM-DD HH:MM:SS` for a unix timestamp.
pub fn utc(timestamp: u64) -> String {
    let (year, month, day) = civil_from_days((timestamp / 86_400) as i64);
    let secs = timestamp % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// UTC `HH:MM` for chart axes.
pub fn clock(timestamp: u64) -> String {
    let secs = timestamp % 86_400;
    format!("{:02}:{:02}", secs / 3600, secs % 3600 / 60)
}

/// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Percentage with two decimals.
pub fn percent(fraction: f64) -> String {
    format!("{:.2}%", fraction * 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashrate_units() {
        assert_eq!(hashrate(0.0), "0 H/s");
        assert_eq!(hashrate(999.0), "999 H/s");
        assert_eq!(hashrate(1_500.0), "1.50 kH/s");
        assert_eq!(hashrate(12.34e12), "12.3 TH/s");
        assert_eq!(hashrate(f64::NAN), "0 H/s");
    }

    #[test]
    fn test_short() {
        assert_eq!(short("abc"), "abc");
        assert_eq!(short("0123456789abcdef0123456789"), "01234567…23456789");
    }

    #[test]
    fn test_ago() {
        assert_eq!(ago(100, 58), "42s ago");
        assert_eq!(ago(10_000, 10_000 - 7200), "2h ago");
        assert_eq!(ago(5, 10), "0s ago");
    }

    #[test]
    fn test_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(1_792_675_942), "2026-10-22 13:32:22");
        assert_eq!(clock(1_792_675_942), "13:32");
    }
}
