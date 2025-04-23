use p2poolv2::shares::chain::chain::Chain;
use p2poolv2::shares::store::Store;
use serde::Serialize;
use std::error::Error;

/// Structure to hold chain information
#[derive(Serialize)]
struct ChainInfo {
    genesis_block_hash: Option<String>,
    chain_tip_height: Option<u32>,
    total_work: String,
    chain_tip_blockhash: Option<String>,
    total_shares: u64,
}

/// Implementation of the info command
pub fn execute(store: Store, _filter: &Option<String>) -> Result<(), Box<dyn Error>> {
    // Create a Chain instance from the store
    let chain = Chain::new(store);

    // Get genesis block hash
    let genesis_block_hash = chain.genesis_block_hash.map(|hash| format!("{:?}", hash));

    // Get chain tip height
    let chain_tip_height = chain.get_tip_height();

    // Get chain tip blockhash
    let chain_tip_blockhash = chain.chain_tip.map(|hash| format!("{:?}", hash));

    // Get total work (difficulty)
    let total_work = format!("{:?}", chain.total_difficulty);

    // Count total number of shares in the chain
    let mut total_shares = 0;
    if let Some(height) = chain_tip_height {
        for h in 0..=height {
            let blockhashes = chain.store.get_blockhashes_for_height(h);
            total_shares += blockhashes.len() as u64;
        }
    }

    // Create info object
    let info = ChainInfo {
        genesis_block_hash,
        chain_tip_height,
        total_work,
        chain_tip_blockhash,
        total_shares,
    };

    // Serialize to JSON and print
    println!("{}", serde_json::to_string_pretty(&info)?);

    Ok(())
}
