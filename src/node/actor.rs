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
use tracing::{error, info}; 
use tokio::sync::oneshot;


/// NodeHandle provides an interface to interact with a Node running in a separate task
#[derive(Clone)]
pub struct NodeHandle {
    // The channel to send commands to the Node Actor
    command_tx: mpsc::Sender<Command>,
}

impl NodeHandle {
    /// Create a new Node and return a handle to interact with it
    pub async fn new(config: Config) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error>> {
        let (command_tx, command_rx) = mpsc::channel::<Command>(32);
        let (node_actor, stopping_rx) = NodeActor::new(config, command_rx)?;
        tokio::spawn(async move {
            node_actor.run().await;
        });
        Ok((Self { command_tx }, stopping_rx))
    }

}

/// NodeActor runs the Node in a separate task and handles all its events
struct NodeActor {
    node: Node,
    command_rx: mpsc::Receiver<Command>,
    stopping_tx: oneshot::Sender<()>,
}

impl NodeActor {
    fn new(config: Config, command_rx: mpsc::Receiver<Command>) -> Result<(Self, oneshot::Receiver<()>), Box<dyn Error>> {
        let node = Node::new(&config)?;
        let (stopping_tx, stopping_rx) = oneshot::channel();
        Ok((Self { node, command_rx, stopping_tx }, stopping_rx))
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                event = self.node.swarm.select_next_some() => {
                    self.node.handle_swarm_event(event);
                },
                command = self.command_rx.recv() => {
                    match command {
                        Some(command) => {
                            if let Err(e) = self.node.handle_command(command) {
                                error!("Error handling command: {}", e);
                            }
                        }
                        None => {
                            info!("Stopping node actor on channel close");
                            self.stopping_tx.send(()).unwrap();
                            break;
                        }
                    }
                }
            }
        }
    }
}
