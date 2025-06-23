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

mod cli;
mod configuration;
mod event_handler;

use ldk_node::Builder;

use ldk_node::bitcoin::Network;

use cli::run_node_cli;
use configuration::{parse_config, NodeConfig};
use event_handler::handle_events;
use std::sync::Arc;

// building node from config
async fn make_node(node_config: NodeConfig) -> ldk_node::Node {
    let mut builder = Builder::new();

    // Convert string to Network enum
    let network = match node_config.network.to_lowercase().as_str() {
        "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "testnet4" => Network::Testnet, // alias if needed
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => panic!("Unsupported network type: {}", other),
    };

    builder.set_network(network);
    builder.set_chain_source_esplora(node_config.esplora_url, None);
    builder.set_gossip_source_rgs(node_config.rgs_server_url);
    builder.set_storage_dir_path(node_config.storage_dir_path);
    let _ = builder.set_listening_addresses(vec![node_config
        .listening_addresses
        .parse()
        .unwrap_or_else(|_| {
            panic!(
                "Invalid listening address: {}",
                node_config.listening_addresses
            )
        })]);
    let _ = builder.set_node_alias(node_config.node_alias.clone());
    let node = builder.build().unwrap();
    node.start().unwrap();
    let public_key = node.node_id();
    let listening_addresses = node.listening_addresses().unwrap();
    println!("Listening on: {:?}", listening_addresses);
    if let Some(first_address) = listening_addresses.first() {
        println!(
            "\nActor Role: {}\nPublic Key: {}\nInternet Address: {}\n",
            node_config.node_alias, public_key, first_address
        );
    } else {
        println!("No listening addresses found");
    }
    node
}

#[tokio::main]
async fn main() {
    let node_config = parse_config("config.toml").expect("Failed to parse configuration file");

    println!("Node configuration: {:?}", node_config);

    let node = make_node(node_config).await;
    let node = Arc::new(node);

    // tokio runtime for spawning in background (event handler)
    let runtime = tokio::runtime::Runtime::new().unwrap();
    println!("Spawning event handler task");
    let node_clone = node.clone();
    let event_loop_handle = runtime.handle().spawn(async move {
        handle_events(&node_clone).await; // Ensure .await here
    });

    run_node_cli(node.clone()).await;

    println!("Stopping the node...");
    node.stop().unwrap();

    println!("Waiting for event handler task to complete...");
    if let Err(e) = event_loop_handle.await {
        eprintln!("Event handler task failed: {}", e);
    }
}
