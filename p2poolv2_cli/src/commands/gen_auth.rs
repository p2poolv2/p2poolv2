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

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p2poolv2_lib::auth::password_to_hmac;
use rand::Rng;
use std::error::Error;

/// Generate a 16-byte hex salt (32 hex characters)
fn generate_salt() -> String {
    let mut rng = rand::thread_rng();
    let salt_bytes: [u8; 16] = rng.r#gen();
    hex::encode(salt_bytes)
}

/// Generate a 32-byte URL-safe base64 password
fn generate_password() -> String {
    let mut rng = rand::thread_rng();
    let password_bytes: [u8; 32] = rng.r#gen();
    URL_SAFE_NO_PAD.encode(password_bytes)
}

/// Execute the gen-auth command
pub fn execute(username: String, password: Option<String>) -> Result<(), Box<dyn Error>> {
    // Determine password (generate, prompt, or use provided)
    let password = match password {
        None => generate_password(),
        Some(ref p) if p == "-" => rpassword::prompt_password("Enter password: ")?,
        Some(p) => p,
    };

    // Generate salt
    let salt = generate_salt();

    // Compute HMAC
    let hmac = password_to_hmac(&salt, &password)
        .map_err(|error| format!("Failed to compute HMAC: {error}"))?;

    // Display results in an easy-to-copy format
    println!("\n=== API Authentication Credentials ===\n");
    println!("Username: {username}");
    println!("Password: {password}");
    println!("Salt:     {salt}");
    println!("HMAC:     {hmac}");
    println!("\n=== Add to config.toml ===\n");
    println!("auth_user = \"{username}\"");
    println!("auth_token = \"{salt}${hmac}\"");
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt() {
        let salt = generate_salt();
        assert_eq!(salt.len(), 32); // 16 bytes = 32 hex chars
        // Verify it is valid hex
        assert!(hex::decode(&salt).is_ok());
    }

    #[test]
    fn test_generate_password() {
        let password = generate_password();
        // URL-safe base64 encoding of 32 bytes should be around 43 chars
        assert!(password.len() >= 40 && password.len() <= 50);
        // Verify it is valid base64
        assert!(URL_SAFE_NO_PAD.decode(&password).is_ok());
    }

    #[test]
    fn test_execute_with_auto_generated_password() {
        // Smoke test: execute should not fail with auto-generated password
        let result = execute("testuser".to_string(), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_with_custom_password() {
        // Smoke test: execute should not fail with custom password
        let result = execute("testuser".to_string(), Some("mypassword123".to_string()));
        assert!(result.is_ok());
    }
}
