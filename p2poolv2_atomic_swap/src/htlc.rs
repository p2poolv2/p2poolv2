use crate::bitcoin::p2tr2;


use crate::swap::{HTLCType, Swap};
use ldk_node::bitcoin::{Address,  KnownHrp, Transaction};
use std::error::Error;
use crate::bitcoin::utils::Utxo;

pub fn generate_htlc_address(swap: &Swap) -> Result<Address, Box<dyn Error>> {
    // need to removed
    let network = KnownHrp::Testnets;
    match swap.from_chain.htlc_type {
        HTLCType::P2tr2 => {
            // Call P2TR2 address generation from p2tr2.rs
            let address = p2tr2::generate_p2tr_address(swap, network)?.0;
            return Ok(address);
        }
        HTLCType::P2wsh2 => {
            // Placeholder for P2WSH2 address generation (to be implemented in p2wsh2.rs)
            Err("P2WSH2 address generation not yet implemented".into())
            // Future implementation: p2wsh2::generate_p2wsh_address(swap, network)
        }
    }
}

pub fn redeem_htlc_address(
    swap: &Swap,
    preimage: &str,
    receiver_private_key: &str,
    utxos: Vec<Utxo>,
    transfer_to_address: &Address,
    
) -> Result<Transaction, Box<dyn Error>> {
    // need to removed
    let network = KnownHrp::Testnets;
    match swap.from_chain.htlc_type {
        HTLCType::P2tr2 => {
            // Call P2TR2 address generation from p2tr2.rs
            p2tr2::redeem_taproot_htlc(
                swap,
                preimage,
                receiver_private_key,
                utxos,            
                transfer_to_address,
                3,
                network,
            )
            .map_err(|e| Box::new(e) as Box<dyn Error>)
        }
        HTLCType::P2wsh2 => {
            // Placeholder for P2WSH2 address generation (to be implemented in p2wsh2.rs)
            Err("Need to implemet p2wsh2 atomic swap redeem function".into())
            // Future implementation: p2wsh2::generate_p2wsh_address(swap, network)
        }
    }
}
