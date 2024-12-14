// Copyright (C) 2024 [Kulpreet Singh]
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

use libp2p::futures::StreamExt;
use tokio::sync::mpsc;
use std::error::Error;
use crate::config::Config;
use crate::command::Command;
use crate::node::Node;
use tracing::error; 
use tokio::sync::oneshot;

/// NodeHandle provides an interface to interact with a Node running in a separate task
#[derive(Clone)]
pub struct NodeHandle {
    command_tx: mpsc::Sender<Command>,
}

impl NodeHandle {
    /// Create a new Node and return a handle to interact with it
    pub async fn new(config: Config, stop_tx: oneshot::Sender<()>) -> Result<Self, Box<dyn Error>> {
        let (command_tx, command_rx) = mpsc::channel(32);
        
        // Create and spawn the node actor
        let node_actor = NodeActor::new(config, command_rx, stop_tx)?;
        tokio::spawn(node_actor.run());

        Ok(Self { command_tx })
    }

    /// Send a command to the node
    pub async fn send_command(&self, command: Command) -> Result<(), Box<dyn Error>> {
        self.command_tx.send(command).await?;
        Ok(())
    }
}

/// NodeActor runs the Node in a separate task and handles all its events
struct NodeActor {
    node: Node,
    command_rx: mpsc::Receiver<Command>,
    stop_tx: oneshot::Sender<()>,
}

impl NodeActor {
    fn new(config: Config, command_rx: mpsc::Receiver<Command>, stop_tx: oneshot::Sender<()>) -> Result<Self, Box<dyn Error>> {
        let node = Node::new(&config)?;
        Ok(Self { node, command_rx, stop_tx })
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                Some(command) = self.command_rx.recv() => {
                    match self.node.handle_command(command) {
                        Ok(continue_running) => {
                            if !continue_running {
                                self.stop_tx.send(()).unwrap();
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Error handling command: {}", e);
                            break;
                        }
                    }
                }
                event = self.node.swarm.select_next_some() => {
                    self.node.handle_swarm_event(event);
                }
            }
        }
    }
}
