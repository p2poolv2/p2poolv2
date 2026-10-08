// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::logging::setup_logging;
use std::process::ExitCode;
use tracing::info;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, env("P2POOL_CONFIG"))]
    config: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("Failed to load config: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Hold guards to keep non-blocking writers alive
    let _guards = match setup_logging(&config.logging) {
        Ok(guards) => guards,
        Err(err) => {
            // no logger yet
            eprintln!("Failed to load config: {err}");
            return ExitCode::FAILURE;
        }
    };

    info!(
        "Running on {} network (git: {})",
        &config.stratum.network,
        env!("GIT_VERSION")
    );

    let (_handles, runner) = match p2poolv2_node::build_node(config).await {
        Ok(result) => result,
        Err(exit_code) => return exit_code,
    };

    runner.run().await
}
