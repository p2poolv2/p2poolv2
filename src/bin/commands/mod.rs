pub mod info;

// Re-export the shared store functionality
pub mod store {
    use p2poolv2::shares::store::Store;
    use std::error::Error;
    use std::path::PathBuf;

    /// Open a store from the given path
    pub fn open_store(store_path: &PathBuf) -> Result<Store, Box<dyn Error>> {
        println!("Opening store in read-only mode: {:?}", store_path);
        
        let path_str = store_path.to_str().expect("Invalid path").to_string();
        Store::new(path_str).map_err(|e| {
            println!("Failed to open store: {}", e);
            e
        })
    }
}