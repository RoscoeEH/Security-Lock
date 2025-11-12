use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::utils::*;

type HmacSha256 = Hmac<Sha256>;

pub fn hmac_sign(
    message: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)?;
    mac.update(message);

    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn hmac_verify(
    message: &[u8],
    key: &[u8],
    signature: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)?;
    mac.update(message);

    mac.verify_slice(signature)?;
    Ok(())
}

// Uses argon2 with m_cost 256*1024, t_cost 8, and p_cost 4. Outputs 256-bit key.
pub fn derive_key(
    password: String,
    salt: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let params = Params::new(256 * 1024, 8, 4, Some(32))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_e| "Argon2 hashing failed")?;

    Ok(key)
}

// ChaCha20Poly1305 encryption with a 256-bit key and 96-bit nonce
#[allow(deprecated)] // from_slice is deprecated, look into update later
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".into());
    }
    if nonce.len() != 12 {
        return Err("Nonce must be 12 bytes".into());
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(ciphertext)
}

// ChaCha20Poly1305 decryption with a 256-bit key and 96-bit nonce
#[allow(deprecated)] // from_slice is deprecated, look into update later
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if key.len() != 32 {
        return Err("Key must be 256 bits".into());
    }
    if nonce.len() != 12 {
        return Err("Nonce must be 96 bits".into());
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}
