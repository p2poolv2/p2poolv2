// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p2poolv2_lib::auth::password_to_hmac;
use rand::RngExt;
use std::error::Error;

/// Generate a 16-byte hex salt (32 hex characters)
fn generate_salt() -> String {
    let mut rng = rand::rng();
    let salt_bytes: [u8; 16] = rng.random();
    hex::encode(salt_bytes)
}

/// Generate a 32-byte URL-safe base64 password
fn generate_password() -> String {
    let mut rng = rand::rng();
    let password_bytes: [u8; 32] = rng.random();
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
