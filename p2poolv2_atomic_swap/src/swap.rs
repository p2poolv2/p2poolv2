use rocksdb::{DB, Options};
use serde::{Deserialize, Serialize};
use ciborium;
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
    pub htlc_type: Option<HTLCType>, // Optional HTLC type for Lightning
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

fn create_swap(swap: &Swap, db_path: &str) -> Result<String, Box<dyn Error>> {
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

fn retrieve_swap(db_path: &str, key: &str) -> Result<Option<Swap>, Box<dyn Error>> {
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



#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    #[ignore]
    fn test_create_swap() -> Result<(), Box<dyn Error>> {
        // Create a temporary directory for the database
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().to_str().ok_or("Invalid temp dir path")?;

        // Create a sample swap
        let swap = Swap {
            payment_hash: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4".to_string(),
            from_chain: Bitcoin {
                initiator_pubkey: "4e912a14d20aceb906a3b60233919457b75c18a0ac5907b76634b503a4aaae2c".to_string(),
                responder_pubkey: "03f59e894abe8451f54493a7f2ab0fd5e62362f4574b6e8814d2b5b12bff401d9d".to_string(),
                timelock: 100,
                amount: 500000,
                htlc_type: HTLCType::P2tr2,
            },
            to_chain: Lightning {
                timelock: 2000,
                amount: 500000,
                htlc_type: None,
            },
        };

        // Test 1: Create first swap and verify key
        let swap1_key = create_swap(&swap, db_path)?;
        println!("Created swap with key: {}", swap1_key);
        assert_eq!(swap1_key, "swap_1", "Expected first swap key to be 'swap_1'");

        // Test 2: Retrieve and verify the stored swap
        let retrieved_swap = retrieve_swap(db_path, &swap1_key)?;
        assert_eq!(
            Some(swap),
            retrieved_swap,
            "Retrieved swap does not match original"
        );

        // Print the retrieved swap for debugging
        println!("Retrieved swap: {:?}", retrieved_swap);
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_create_multiple_swaps() -> Result<(), Box<dyn Error>> {
        // Create a temporary directory for the database
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().to_str().ok_or("Invalid temp dir path")?;

        // Create first swap
        let swap1 = Swap {
            payment_hash: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4".to_string(),
            from_chain: Bitcoin {
                initiator_pubkey: "4e912a14d20aceb906a3b60233919457b75c18a0ac5907b76634b503a4aaae2c".to_string(),
                responder_pubkey: "03f59e894abe8451f54493a7f2ab0fd5e62362f4574b6e8814d2b5b12bff401d9d".to_string(),
                timelock: 100,
                amount: 500000,
                htlc_type: HTLCType::P2tr2,
            },
            to_chain: Lightning {
                timelock: 2000,
                amount: 500000,
                htlc_type: None,
            },
        };

        // Create second swap
        let swap2 = Swap {
            payment_hash: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            from_chain: Bitcoin {
                initiator_pubkey: "init_pubkey_abc".to_string(),
                responder_pubkey: "resp_pubkey_def".to_string(),
                timelock: 2500,
                amount: 750000,
                htlc_type: HTLCType::P2wsh2,
            },
            to_chain: Lightning {
                timelock: 1500,
                amount: 750000,
                htlc_type: Some(HTLCType::P2wsh2),
            },
        };

        // Test 1: Create first swap and verify key
        let swap1_key = create_swap(&swap1, db_path)?;
        assert_eq!(swap1_key, "swap_1", "Expected first swap key to be 'swap_1'");

        // Test 2: Create second swap and verify key increment
        let swap2_key = create_swap(&swap2, db_path)?;
        assert_eq!(swap2_key, "swap_2", "Expected second swap key to be 'swap_2'");

        // Test 3: Retrieve and verify both swaps
        let retrieved_swap1 = retrieve_swap(db_path, &swap1_key)?;
        assert_eq!(
            Some(swap1),
            retrieved_swap1,
            "Retrieved first swap does not match original"
        );

        let retrieved_swap2 = retrieve_swap(db_path, &swap2_key)?;
        assert_eq!(
            Some(swap2),
            retrieved_swap2,
            "Retrieved second swap does not match original"
        );

        // Test 4: Verify counter
        let db = DB::open(&Options::default(), db_path)?;
        let counter = db
            .get(b"swap_counter")?
            .map(|v| String::from_utf8(v).unwrap().parse::<u32>().unwrap())
            .unwrap_or(0);
        assert_eq!(counter, 2, "Expected swap counter to be 2");

        println!("Retrieved first swap: {:?}", retrieved_swap1);
        println!("Retrieved second swap: {:?}", retrieved_swap2);
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_retrieve_non_existent_swap() -> Result<(), Box<dyn Error>> {
        // Create a temporary directory for the database
        let temp_dir = TempDir::new()?;
        let db_path = temp_dir.path().to_str().ok_or("Invalid temp dir path")?;

        // Test: Retrieve a non-existent swap
        let retrieved_swap = retrieve_swap(db_path, "swap_999")?;
        assert_eq!(retrieved_swap, None, "Expected None for non-existent swap key");

        println!("Retrieved non-existent swap: {:?}", retrieved_swap);
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_invalid_db_path() -> Result<(), Box<dyn Error>> {
        // Test: Attempt to create a swap with an invalid database path
        let swap = Swap {
            payment_hash: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4".to_string(),
            from_chain: Bitcoin {
                initiator_pubkey: "4e912a14d20aceb906a3b60233919457b75c18a0ac5907b76634b503a4aaae2c".to_string(),
                responder_pubkey: "03f59e894abe8451f54493a7f2ab0fd5e62362f4574b6e8814d2b5b12bff401d9d".to_string(),
                timelock: 100,
                amount: 500000,
                htlc_type: HTLCType::P2tr2,
            },
            to_chain: Lightning {
                timelock: 2000,
                amount: 500000,
                htlc_type: None,
            },
        };

        // Use an invalid path (e.g., a directory that cannot be created)
        let invalid_path = "/invalid/path/to/db";
        let result = create_swap(&swap, invalid_path);
        assert!(result.is_err(), "Expected error for invalid database path");

        println!("Result for invalid path: {:?}", result);
        Ok(())
    }
}