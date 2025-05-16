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

#[cfg(test)]
mod tests {
    use p2poolv2_lib::stratum::{
        self,
        messages::{Request, Response},
        server::StratumServer,
    };
    use std::io::{Read, Write};
    use std::net::SocketAddr;
    use std::net::TcpStream;
    use std::str;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    use tokio::runtime::Runtime;

    #[test_log::test]
    fn test_stratum_server_subscribe() {
        let addr: SocketAddr = "127.0.0.1:9999".parse().expect("Invalid address");
        // Setup server - using Arc so we can access it for shutdown
        let server = Arc::new(StratumServer::new(9999, "127.0.0.1".to_string()));
        let server_for_shutdown = Arc::clone(&server);

        // Create a Tokio runtime for running the async server
        let runtime = Runtime::new().expect("Failed to create runtime");

        // Start server in a separate thread with runtime
        let server_handle = thread::spawn(move || {
            runtime.block_on(async {
                // Instead of await, we use block_on to wait for the server to start
                let _ = server.start().await;
            });
        });

        // More reliable connection with retry logic
        let mut client = None;
        for attempt in 1..=5 {
            thread::sleep(Duration::from_millis(100));
            match TcpStream::connect(addr) {
                Ok(stream) => {
                    client = Some(stream);
                    break;
                }
                Err(e) => {
                    if attempt == 5 {
                        panic!("Failed to connect after multiple attempts: {}", e);
                    }
                    // Otherwise, continue retrying
                }
            }
        }
        let mut client = client.expect("Failed to connect to StratumServer");

        // Send subscribe message
        let subscribe_msg = Request::new_subscribe(1, "agent".to_string(), "1.0".to_string(), None);

        // Serialize the subscribe message
        let subscribe_str =
            serde_json::to_string(&subscribe_msg).expect("Failed to serialize subscribe message");
        client
            .write_all((subscribe_str + "\n").as_bytes()) // Note: Added newline
            .expect("Failed to send subscribe message");

        // Read response
        let mut buffer = [0; 1024];
        let bytes_read = client.read(&mut buffer).expect("Failed to read response");
        let response_str = str::from_utf8(&buffer[..bytes_read]).expect("Invalid UTF-8");
        println!("Response: {}", response_str);

        // Parse and validate response
        let response_message: Response =
            serde_json::from_str(response_str).expect("Failed to deserialize response as Response");

        assert_eq!(
            response_message.id,
            Some(stratum::messages::Id::Number(1)),
            "Response ID doesn't match request ID"
        );
        assert!(
            response_message.result.is_some(),
            "Response missing 'result' field"
        );
        assert!(
            response_message.error.is_none(),
            "Response should not contain 'error' field"
        );
        response_message.result.unwrap();

        // Clean up client connection
        drop(client);

        // Test the server shutdown functionality
        let shutdown_runtime = Runtime::new().expect("Failed to create shutdown runtime");
        let shutdown_result =
            shutdown_runtime.block_on(async { server_for_shutdown.shutdown().await });

        // Verify shutdown completed without errors
        assert!(
            shutdown_result.is_ok(),
            "Server shutdown failed: {:?}",
            shutdown_result
        );

        // Try to connect again - should fail because server is shut down
        thread::sleep(Duration::from_millis(500));

        // Instead of just a single connection attempt:
        match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Ok(_) => {
                // If we got a connection, let's try to actually use it
                // to confirm it's a real Stratum server and not just an open socket
                let mut test_stream = TcpStream::connect(addr)
                    .expect("Connection succeeded but stream creation failed");

                // Try sending a subscribe message
                let test_msg =
                    Request::new_subscribe(999, "agent".to_string(), "1.0".to_string(), None);

                let test_str =
                    serde_json::to_string(&test_msg).expect("Failed to serialize test message");

                // If we can write and then read a proper response, the server is still running
                if test_stream.write_all((test_str + "\n").as_bytes()).is_ok() {
                    let mut buffer = [0; 1024];
                    match test_stream.read(&mut buffer) {
                        Ok(bytes_read) if bytes_read > 0 => {
                            panic!(
                                "Server appears to still be running and responsive after shutdown!"
                            );
                        }
                        _ => {
                            // We couldn't read a response - this is good, server might be in process of shutting down
                            println!("Connection succeeded but server did not respond - likely in shutdown process");
                        }
                    }
                } else {
                    println!("Connection succeeded but couldn't write - server might be partially shut down");
                }
            }
            Err(e) => {
                println!("Connection after shutdown correctly failed: {}", e);
                // This is expected behavior
            }
        }

        // Wait for the server thread to complete
        if let Err(e) = server_handle.join() {
            println!("Server thread did not exit cleanly: {:?}", e);
        }
    }
}
