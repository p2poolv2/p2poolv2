mod p2tr2;
mod p2wsh2;
mod tx_utils;
mod utils;
mod checks;

use crate::swap::{Swap, HTLCType};
use ldk_node::bitcoin::{Address, KnownHrp};
use std::error::Error;

pub fn generate_htlc_address(swap: &Swap) -> Result<Address, Box<dyn Error>> {
    // need to removed 
    let network = KnownHrp::Testnets;
    match swap.from_chain.htlc_type {
        HTLCType::P2tr2 => {
            // Call P2TR2 address generation from p2tr2.rs
            p2tr2::generate_p2tr_address(swap, network)
        }
        HTLCType::P2wsh2 => {
            // Placeholder for P2WSH2 address generation (to be implemented in p2wsh2.rs)
            Err("P2WSH2 address generation not yet implemented".into())
            // Future implementation: p2wsh2::generate_p2wsh_address(swap, network)
        }
    }
}
