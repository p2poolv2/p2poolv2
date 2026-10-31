// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use clap::Parser;
use p2poolv2_lib::config::Config;
use p2poolv2_lib::logging::setup_logging;
use std::process::ExitCode;
use tracing::info;
use std::ffi::OsString;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, env = "P2POOL_CONFIG")]
    config: String,
    
    #[arg(long = "set", value_name = "KEY=VALUE", num_args = 1.., hide = true)]
    set: Vec<String>,
}

pub fn expand_dynamic_args(input: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    // Target, if we are provided with the following:

    // --P2POOL_BITCOINRPC__URL= -> --set bitcoinrpc.url=
    // --bitcoinrpc-URL= -> --set bitcoinrpc.url=
    // --ApiConfig-cors--allowed= -> --set apiconfig.cors_allowed= 
    
    // We will expand the args to use the set command as well as normalizing them.

    // Disclaimers:
    // You must separate your key and value with an equal sign.
    // You must have a -- or a _ when key has a _.
    let mut input_iter = input.into_iter();
    let mut output = vec![input_iter.next().unwrap_or_default()];
    for arg in input_iter {
        let Some(text) = arg.to_str() else {
            output.push(arg);
            continue;
        };
        // --P2POOL_BITCOINRPC__URL= -> BITCOINRPC__URL=
        // --bitcoinrpc-URL= -> bitcoinrpc-URL=
        // --ApiConfig-cors--allowed= -> ApiConfig--cors_allowed=
        let mut prefix_removed = text;
        if let Some(stripped) = prefix_removed.strip_prefix("--P2POOL_") {
            prefix_removed = stripped;
        } else if let Some(stripped) = prefix_removed.strip_prefix("--P2POOL-") {
            prefix_removed = stripped;
        } else if let Some(stripped) = prefix_removed.strip_prefix("--") {
            prefix_removed = stripped;
        }

        if let Some((env_key, value)) = prefix_removed.split_once('=') {            
            // BITCOINRPC__URL= -> BITCOINRPC.URL=
            // bitcoinrpc-URL= -> bitcoinrpc-URL=
            // ApiConfig-cors--allowed= -> ApiConfig-cors_allowed=
            let mut key = env_key.to_ascii_lowercase();
            key = key.replace("__", ".");
            key = key.replace("--", "_");
            key = key.replace("-", ".");
            
            output.push("--set".into());
            output.push(format!("{key}={value}").into());
            continue;
        }
        output.push(arg);
    }
    output
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse_from(expand_dynamic_args(std::env::args_os()));

    let config = match Config::load_with_command_args(&args.config, &args.set) {
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

#[cfg(test)]
mod tests {
    use super::*; 
    #[test]
    fn test_expand_dynamic_args() {
        let mock_input = vec![
            OsString::from("p2poolv2"),
            OsString::from("--help"),
            OsString::from("--version"),
            OsString::from("--"),
            OsString::from("--config config.sample.toml"),
            OsString::from("--P2POOL_BITCOINRPC__URL=http://127.0.0.1:48332"),
            OsString::from("--ApiConfig-cors_allowed=true"),
            OsString::from("--ApiConfig-cors--allowed=true"),
            OsString::from("--bitcoinrpc-URL=http://127.0.0.1:48332"),
            OsString::from("--NetworkConfig-max_established_per_peer=12")
        ];

        let expected_output = vec![
            OsString::from("p2poolv2"),
            OsString::from("--help"),
            OsString::from("--version"),
            OsString::from("--"),
            OsString::from("--config config.sample.toml"),
            OsString::from("--set"),
            OsString::from("bitcoinrpc.url=http://127.0.0.1:48332"),
            OsString::from("--set"),
            OsString::from("apiconfig.cors_allowed=true"),
            OsString::from("--set"),
            OsString::from("apiconfig.cors_allowed=true"),
            OsString::from("--set"),
            OsString::from("bitcoinrpc.url=http://127.0.0.1:48332"),
            OsString::from("--set"),
            OsString::from("networkconfig.max_established_per_peer=12")
        ];
        assert_eq!(expand_dynamic_args(mock_input), expected_output)
    }
}
