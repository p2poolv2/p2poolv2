mod commands;

use clap::{Parser, Subcommand};
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
    Info {
        /// Optional filter to show only specific information
        #[arg(short, long)]
        filter: Option<String>,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Check if store path is provided and handle it
    if let Some(store_path) = cli.store_path {
        let store = commands::store::open_store(&store_path)?;

        // Handle command if provided
        match &cli.command {
            Some(Commands::Info { filter }) => {
                commands::info::execute(store, filter)?;
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
