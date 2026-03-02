// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of password using salt as key, returning the hex-encoded result.
pub fn password_to_hmac(salt: &str, password: &str) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(salt.as_bytes())
        .map_err(|error| format!("Failed to create HMAC: {error}"))?;
    mac.update(password.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Build a Basic auth header value from username and password.
pub fn build_basic_auth_header(username: &str, password: &str) -> String {
    let credentials = format!("{username}:{password}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
    format!("Basic {encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_to_hmac() {
        let salt = "0123456789abcdef0123456789abcdef";
        let password = "testpassword123";
        let hmac = password_to_hmac(salt, password).unwrap();

        // HMAC-SHA256 produces 32 bytes = 64 hex chars
        assert_eq!(hmac.len(), 64);
        // Verify it is valid hex
        assert!(hex::decode(&hmac).is_ok());

        // Verify deterministic (same inputs produce same output)
        let hmac2 = password_to_hmac(salt, password).unwrap();
        assert_eq!(hmac, hmac2);
    }

    #[test]
    fn test_password_to_hmac_different_inputs() {
        let salt = "0123456789abcdef0123456789abcdef";
        let hmac1 = password_to_hmac(salt, "password1").unwrap();
        let hmac2 = password_to_hmac(salt, "password2").unwrap();

        // Different passwords should produce different HMACs
        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_build_basic_auth_header() {
        let header = build_basic_auth_header("admin", "secret");
        assert!(header.starts_with("Basic "));

        let encoded = &header[6..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(decoded_str, "admin:secret");
    }
}
