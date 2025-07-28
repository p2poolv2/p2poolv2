use ciborium;
use rocksdb::{Options, DB};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::io::Cursor;
use log::{info, error};
use thiserror::Error as ThisError;

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

#[derive(ThisError, Debug)]
pub enum SwapError {
    #[error("Failed to open database: {0}")]
    DatabaseOpenError(#[from] rocksdb::Error),
    #[error("Failed to parse counter: {0}")]
    CounterParseError(String),
    #[error("Failed to read counter from database: {0}")]
    CounterReadError(String),
    #[error("Failed to serialize swap to CBOR: {0}")]
    SerializationError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error("Failed to deserialize swap from CBOR: {0}")]
    DeserializationError(#[from] ciborium::de::Error<std::io::Error>),
    #[error("Failed to access database: {0}")]
    DatabaseAccessError(String),
}

pub fn create_swap(swap: &Swap, db_path: &str) -> Result<String, SwapError> {
    // Configure RocksDB options
    let mut options = Options::default();
    options.create_if_missing(true);
    info!("Configuring RocksDB with create_if_missing=true for path: {}", db_path);

    // Open the database
    let db = DB::open(&options, db_path).map_err(|e| {
        error!("Failed to open database at {}: {}", db_path, e);
        SwapError::DatabaseOpenError(e)
    })?;

    // Find the next order ID
    let mut next_id = 1;
    let counter_key = b"swap_counter";

    if let Ok(Some(value)) = db.get(counter_key) {
        let counter_str = String::from_utf8(value).map_err(|e| {
            error!("Failed to read counter as UTF-8: {}", e);
            SwapError::CounterReadError(e.to_string())
        })?;
        next_id = counter_str.parse::<u32>().map_err(|e| {
            error!("Failed to parse counter '{}' as u32: {}", counter_str, e);
            SwapError::CounterParseError(e.to_string())
        })? + 1;
    }
    info!("Next swap ID: {}", next_id);

    // Serialize the object to CBOR
    let mut serialized = Vec::new();
    ciborium::into_writer(swap, &mut serialized)?;
    info!("Serialized swap to CBOR, size: {} bytes", serialized.len());

    // Create swap key
    let swap_key = format!("swap_{}", next_id);

    // Store the swap in RocksDB
    db.put(swap_key.as_bytes(), &serialized).map_err(|e| {
        error!("Failed to store swap {} in database: {}", swap_key, e);
        SwapError::DatabaseAccessError(e.to_string())
    })?;

    // Update the counter
    db.put(counter_key, next_id.to_string().as_bytes()).map_err(|e| {
        error!("Failed to update swap counter to {}: {}", next_id, e);
        SwapError::DatabaseAccessError(e.to_string())
    })?;

    info!("Created swap {}: {:?}", swap_key, swap);

    Ok(swap_key)
}

pub fn retrieve_swap(db_path: &str, key: &str) -> Result<Option<Swap>, SwapError> {
    // Configure RocksDB options
    let mut options = Options::default();
    options.create_if_missing(true);
    info!("Configuring RocksDB with create_if_missing=true for path: {}", db_path);

    // Open the database
    let db = DB::open(&options, db_path).map_err(|e| {
        error!("Failed to open database at {}: {}", db_path, e);
        SwapError::DatabaseOpenError(e)
    })?;

    // Retrieve the serialized object
    info!("Retrieving swap for key: {}", key);
    match db.get(key.as_bytes()).map_err(|e| {
        error!("Failed to retrieve swap {} from database: {}", key, e);
        SwapError::DatabaseAccessError(e.to_string())
    })? {
        Some(value) => {
            info!("Found swap data for key {}, size: {} bytes", key, value.len());
            // Deserialize the CBOR data back to the object
            let deserialized: Swap = ciborium::from_reader(Cursor::new(value))?;
            info!("Deserialized swap: {:?}", deserialized);
            Ok(Some(deserialized))
        }
        None => {
            info!("No swap found for key: {}", key);
            Ok(None)
        }
    }
}