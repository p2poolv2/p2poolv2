// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
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

// Import the library explicitly
extern crate p2poolv2_lib;

mod cli_commands;

// Now use the external crate with its name
use clap::{Parser, Subcommand};
use p2poolv2_lib::shares::chain::chain::Chain;
use std::error::Error;
use std::path::PathBuf;

/// P2Pool v2 CLI utility
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the RocksDB store
    #[arg(short, long)]
    store_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List information about the store
    Info,
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Check if store path is provided and handle it
    if let Some(store_path) = cli.store_path {
        let store = cli_commands::store::open_store(&store_path)?;
        let chain = Chain::new(store);

        // Handle command if provided
        match &cli.command {
            Some(Commands::Info) => {
                cli_commands::info::execute(chain)?;
            }
            None => {
                println!("No command specified. Use --help for usage information.");
            }
        }
    } else {
        println!("No store path provided. Use --help for usage information.");
    }

    Ok(())
}
