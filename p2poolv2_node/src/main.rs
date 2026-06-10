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

use clap::Parser;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::logging::setup_logging;
use std::process::ExitCode;
use tracing::{error, info};

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
