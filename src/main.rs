use clap::Parser;
use std::error::Error;
use tracing_subscriber::EnvFilter;
use tracing::debug;
mod node;
use crate::node::Node;
mod config;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Parse command line arguments
    let args = Args::parse();
    debug!("Parsed args: {:?}", args);

    // Load configuration
    let config = config::Config::load(&args.config)?;

    let mut node = Node::new(&config)?;
    node.run().await;

    Ok(())
}
