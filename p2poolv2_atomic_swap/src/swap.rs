use ciborium;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::Cursor;

// Define the enum for HTLC types
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum HTLCType {
    P2tr2,  // p2tr with 2 spending path
    P2wsh2, // p2wsh with 2 spending path
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Lightning {
    pub timelock: u64,
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Bitcoin {
    pub initiator_pubkey: String, // No Option, use "" as default
    pub responder_pubkey: String, // No Option, use "" as default
    pub timelock: u64,
    pub amount: u64,
    pub htlc_type: HTLCType, // Required HTLC type for Bitcoin
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Swap {
    pub payment_hash: String,
    pub from_chain: Bitcoin,
    pub to_chain: Lightning,
}

pub fn create_swap(swap: &Swap, db_path: &str) -> Result<String, Box<dyn Error>> {
    // Configure RocksDB options
    let mut options = Options::default();
    options.create_if_missing(true);

    // Open the database
    let db = DB::open(&options, db_path)?;

    // Find the next order ID
    let mut next_id = 1;
    let counter_key = b"swap_counter";

    if let Ok(Some(value)) = db.get(counter_key) {
        let counter_str = String::from_utf8(value)?;
        next_id = counter_str.parse::<u32>()? + 1;
    }

    // Serialize the object to CBOR
    let mut serialized = Vec::new();
    ciborium::into_writer(swap, &mut serialized)?;

    // Create swap key
    let swap_key = format!("swap_{}", next_id);

    // Store the swap in RocksDB
    db.put(swap_key.as_bytes(), &serialized)?;

    // Update the counter
    db.put(counter_key, next_id.to_string().as_bytes())?;

    println!("Created swap {}: {:?}", swap_key, swap);

    Ok(swap_key)
}

pub fn retrieve_swap(db_path: &str, key: &str) -> Result<Option<Swap>, Box<dyn Error>> {
    // Configure RocksDB options
    let mut options = Options::default();
    options.create_if_missing(true);

    // Open the database
    let db = DB::open(&options, db_path)?;

    // Retrieve the serialized object
    match db.get(key.as_bytes())? {
        Some(value) => {
            // Deserialize the CBOR data back to the object
            match ciborium::from_reader(Cursor::new(value)) {
                Ok(deserialized) => Ok(Some(deserialized)),
                Err(e) => Err(Box::new(e)),
            }
        }
        None => Ok(None),
    }
}

