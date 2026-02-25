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

use crate::config::LoggingConfig;
use std::error::Error;
use tracing::debug;
use tracing_appender::non_blocking;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Determines whether console logging should be enabled based on the configuration.
///
/// Returns `(enable_console, is_fallback)` where:
/// - `enable_console`: whether console logging should be enabled
/// - `is_fallback`: whether this is a fallback due to no logging destination being configured
fn should_enable_console(logging_config: &LoggingConfig) -> (bool, bool) {
    let console_explicitly_disabled = logging_config.console == Some(false);
    let file_configured = logging_config.file.is_some();

    if console_explicitly_disabled && !file_configured {
        // Fallback: enable console to prevent silent operation
        (true, true)
    } else {
        (logging_config.console.unwrap_or(true), false)
    }
}

/// Sets up logging according to the logging configuration.
///
/// If both console logging is disabled and no file logging is configured,
/// console logging is enabled as a fallback to prevent silent operation.
pub fn setup_logging(
    logging_config: &LoggingConfig,
) -> Result<Option<non_blocking::WorkerGuard>, Box<dyn Error>> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&logging_config.level));

    let (enable_console, is_fallback) = should_enable_console(logging_config);

    if is_fallback {
        eprintln!(
            "Warning: Console logging disabled but no file configured. Enabling console logging as fallback."
        );
    }

    let console_layer = if enable_console {
        eprintln!("Console logging enabled");
        Some(fmt::layer())
    } else {
        eprintln!("Console logging disabled");
        None
    };

    let (file_layer, guard) = if let Some(file_path) = &logging_config.file {
        debug!("File logging is enabled, writing to: {}", file_path);
        // Create directory structure if it doesn't exist
        if let Some(parent) = std::path::Path::new(file_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file_path = std::path::Path::new(file_path);
        let directory = file_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let filename = file_path
            .file_name()
            .unwrap_or_default()
            .to_str()
            .unwrap_or("p2pool.log");

        debug!(
            "Logging to directory: {}, filename: {}",
            directory.display(),
            filename
        );

        // Configure rolling file appender
        let file_appender = RollingFileAppender::new(
            Rotation::DAILY, // Use daily rotation
            directory,
            filename,
        );

        // Use the non_blocking function directly from tracing_appender
        let (non_blocking_appender, guard) = non_blocking(file_appender);
        let layer = fmt::layer()
            .with_writer(non_blocking_appender)
            .with_ansi(false);

        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    Registry::default()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(console: Option<bool>, file: Option<&str>) -> LoggingConfig {
        LoggingConfig {
            console,
            file: file.map(String::from),
            level: "info".to_string(),
            stats_dir: "./logs/stats".to_string(),
        }
    }

    #[test]
    fn test_console_enabled_by_default_when_not_specified() {
        let config = config_with(None, None);
        let (enable_console, is_fallback) = should_enable_console(&config);

        assert!(enable_console, "Console should be enabled by default");
        assert!(!is_fallback, "Should not be a fallback when using default");
    }

    #[test]
    fn test_console_enabled_when_explicitly_true() {
        let config = config_with(Some(true), None);
        let (enable_console, is_fallback) = should_enable_console(&config);

        assert!(
            enable_console,
            "Console should be enabled when explicitly set to true"
        );
        assert!(
            !is_fallback,
            "Should not be a fallback when explicitly enabled"
        );
    }

    #[test]
    fn test_console_disabled_when_file_configured() {
        let config = config_with(Some(false), Some("./logs/test.log"));
        let (enable_console, is_fallback) = should_enable_console(&config);

        assert!(
            !enable_console,
            "Console should be disabled when file is configured"
        );
        assert!(
            !is_fallback,
            "Should not be a fallback when file is configured"
        );
    }

    #[test]
    fn test_console_fallback_when_disabled_without_file() {
        let config = config_with(Some(false), None);
        let (enable_console, is_fallback) = should_enable_console(&config);

        assert!(enable_console, "Console should be enabled as fallback");
        assert!(is_fallback, "Should indicate this is a fallback");
    }

    #[test]
    fn test_console_enabled_with_file_configured() {
        let config = config_with(Some(true), Some("./logs/test.log"));
        let (enable_console, is_fallback) = should_enable_console(&config);

        assert!(
            enable_console,
            "Console should be enabled alongside file logging"
        );
        assert!(
            !is_fallback,
            "Should not be a fallback when explicitly enabled"
        );
    }

    #[test]
    fn test_console_default_with_file_configured() {
        let config = config_with(None, Some("./logs/test.log"));
        let (enable_console, is_fallback) = should_enable_console(&config);

        assert!(
            enable_console,
            "Console should be enabled by default even with file"
        );
        assert!(!is_fallback, "Should not be a fallback when using default");
    }
}
