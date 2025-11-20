use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pqcrypto_mlkem::mlkem768::*;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use sha2::Sha256;

use std::error::Error;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::constants::*;

type HmacSha256 = Hmac<Sha256>;

// --- Digital Signatures ---
pub fn hmac_sign(message: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)?;
    mac.update(message);

    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn hmac_verify(
    message: &[u8],
    key: &[u8],
    signature: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)?;
    mac.update(message);

    mac.verify_slice(signature)?;
    Ok(())
}

// --- Key Derivation ---

// Uses argon2 with m_cost 256*1024, t_cost 8, and p_cost 4. Outputs 256-bit key.
fn argon2(
    password: String,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(SYM_KEY_SIZE))
        .map_err(|e| format!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; SYM_KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_e| "Argon2 hashing failed")?;

    Ok(key)
}

pub fn argon2_derive_key(
    password: String,
    salt: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    argon2(password, salt, 256 * 1024, 8, 4)
}

// for verification of a user pin
pub fn argon2_pin_hash(pin: String, salt: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    argon2(pin, salt, 64, 2, 1)
}

pub fn hkdf_derive_key(
    key_material: &[u8],
    salt: &[u8],
    counter: &AtomicU64,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), key_material);
    let mut key_vec = [0u8; SYM_KEY_SIZE];
    let info = counter
        .fetch_add(1, Ordering::SeqCst)
        .to_be_bytes()
        .to_vec();
    hk.expand(&info, &mut key_vec)
        .map_err(|_| "HKDF expand failed")?;

    Ok(key_vec.to_vec())
}

// --- Symmetric encryption ---

// ChaCha20Poly1305 encryption with a 256-bit key and 96-bit nonce
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    if key.len() != SYM_KEY_SIZE {
        return Err("Key must be 32 bytes".into());
    }
    if nonce.len() != NONCE_SIZE {
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
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    if key.len() != SYM_KEY_SIZE {
        return Err("Key must be 256 bits".into());
    }
    if nonce.len() != NONCE_SIZE {
        return Err("Nonce must be 96 bits".into());
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

// --- Key Encapsulation ---

pub fn kem_key_gen() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let (pk, sk) = keypair();

    Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
}

pub fn key_encap(
    encap_key_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error + Send + Sync>> {
    let pk = PublicKey::from_bytes(encap_key_bytes).map_err(|_| "Invalid public key bytes")?;

    let (ss, ct) = encapsulate(&pk);

    Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
}

pub fn key_decap(
    decap_key_bytes: &[u8],
    ct_bytes: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let sk = SecretKey::from_bytes(decap_key_bytes).map_err(|_| "Invalid secret key bytes")?;

    let ct = Ciphertext::from_bytes(ct_bytes).map_err(|_| "Invalid ciphertext bytes")?;

    let ss = decapsulate(&ct, &sk);

    Ok(ss.as_bytes().to_vec())
}
