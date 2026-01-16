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
use tracing::info;
use tracing_appender::non_blocking;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Sets up logging according to the logging configuration
pub fn setup_logging(
    logging_config: &LoggingConfig,
) -> Result<Option<non_blocking::WorkerGuard>, Box<dyn Error>> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&logging_config.level));

    let console_layer = if logging_config.console.unwrap_or(true) {
        info!("Console logging enabled");
        Some(fmt::layer())
    } else {
        info!("Console logging disabled");
        None
    };

    let (file_layer, guard) = if let Some(file_path) = &logging_config.file {
        info!("File logging is enabled, writing to: {}", file_path);
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

        info!(
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
