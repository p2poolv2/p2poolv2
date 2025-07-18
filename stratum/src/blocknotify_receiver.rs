// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
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

use std::io::Write;
use std::os::unix::net::UnixStream;

/// The path to the Unix socket used for block notifications.
/// From this bin we can't import the const from work/gbt, so we redefine it here.
pub const SOCKET_PATH: &str = "/tmp/p2pool_blocknotify.sock";

/// A simple program to notify our gbt event loop in stratum server.
///
/// The program is set as the blocknotify option in the bitcoind conf.
fn main() -> std::io::Result<()> {
    // Use default socket path
    let socket_path = SOCKET_PATH;

    // Connect to the socket
    let mut stream = match UnixStream::connect(socket_path) {
        Ok(stream) => stream,
        Err(_e) => {
            println!(
                "P2Pool server not running. No notification sent to {}",
                socket_path
            );
            return Ok(());
        }
    };

    // Write a single byte to trigger the listener
    stream.write_all(b"blocknotify\n")?;

    println!("Block notification sent to {}", socket_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::thread;

    #[test]
    fn test_blocknotify_sender() {
        // Create a temporary socket path for testing
        let socket_path = SOCKET_PATH;

        // Remove the socket file if it already exists
        if Path::new(socket_path).exists() {
            fs::remove_file(socket_path).unwrap();
        }

        // Set up a listener on the socket
        let listener = UnixListener::bind(socket_path).unwrap();

        // Spawn a thread to run the listener
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = Vec::new();
            stream.read_to_end(&mut buffer).unwrap();
            buffer
        });

        // Call the main function
        thread::spawn(|| {
            super::main().unwrap();
        });

        // Wait for the listener thread to receive the data
        let received = handle.join().unwrap();

        assert_eq!(received, b"blocknotify\n");

        // Clean up
        fs::remove_file(socket_path).unwrap_or_default();
    }
}
