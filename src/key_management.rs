use rpassword::read_password;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;

use crate::crypto::*;
use crate::utils::*;

pub fn generate_user_keypair(
    dk_path: String,
    ek_path: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (ek, dk) = kem_key_gen()?;

    // Get encryption needs
    let salt = get_salt();
    let kek = get_kek(&salt, true)?;
    let nonce = get_nonce();
    let protected_key = encrypt(&dk, &kek, &nonce)?;

    overwrite_key_file(ek_path, &ek)?;

    let mut dk_data = Vec::<u8>::new();
    dk_data.extend_from_slice("KEY".as_bytes());
    dk_data.extend_from_slice(&protected_key);
    dk_data.extend_from_slice(&nonce);
    dk_data.extend_from_slice(&salt);
    overwrite_key_file(dk_path, &dk_data)?;

    Ok(())
}

fn decrypt_key_file(key_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Encrypted key format -> "KEY" (3 bytes) | decap key (2416 bytes) | nonce (12 bytes) | salt (16 bytes)
    let magic = &key_bytes[..3];
    let ciphertext = &key_bytes[3..2419];
    let nonce = &key_bytes[2419..2431];
    let salt = &key_bytes[2431..2447];

    // Verify magic
    if magic != "KEY".as_bytes() {
        return Err("Bad PSK magic.".into());
    }

    // Derive kek
    let kek = get_kek(salt, false)?;
    let plaintext_key = match decrypt(ciphertext, &kek, nonce) {
        Ok(key) => key,
        Err(_) => return Err("PSK decryption failed.".into()),
    };

    Ok(plaintext_key)
}

fn get_kek(salt: &[u8], new_password: bool) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Uses default key for dev testing
    if cfg!(debug_assertions) {
        println!("[DEV MODE] Using dev kek");
        let expanded = expand_tilde("config/test_kek.bin");
        let mut file = File::open(&expanded)?;

        let mut key_bytes = Vec::new();
        file.read_to_end(&mut key_bytes)?;

        return Ok(key_bytes);
    }

    // Gets user password
    println!("Enter password: ");
    let password = read_password()?;

    // Confirm password if it is being entered for the first time
    if new_password {
        println!("Re-enter password: ");
        let password_check = read_password()?;
        if password != password_check {
            return Err("Passwords do not match.".into());
        }
    }

    let kek = argon2_derive_key(password, salt)?;

    Ok(kek)
}

// Reads the preshared key file
pub fn get_decap_key(key_path: String) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let expanded = expand_tilde(&key_path);

    let mut file = File::open(&expanded)?;

    let mut key_bytes = Vec::new();
    file.read_to_end(&mut key_bytes)?;

    let decap_key = match key_bytes.len() {
        // Key is encrypted, has header, nonce, signature, etc...
        2447 => decrypt_key_file(&key_bytes)?,
        _ => {
            return Err("Unrecognized PSK format.".into());
        }
    };

    Ok(decap_key)
}

pub fn get_encap_key(key_path: &String) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let expanded = expand_tilde(&key_path);

    let mut file = File::open(&expanded)?;

    let mut key_bytes = Vec::new();
    file.read_to_end(&mut key_bytes)?;

    let psk = match key_bytes.len() {
        // Key is plaintext, raw 256 bits
        1184 => key_bytes,
        _ => {
            return Err("Unrecognized PSK format.".into());
        }
    };

    Ok(psk)
}

pub fn renew_sk(
    sk: &[u8],
    salt: &[u8],
    counter: u64,
) -> Result<Arc<Vec<u8>>, Box<dyn Error + Sync + Send>> {
    if cfg!(debug_assertions) {
        println!("Renewing session key");
    }
    let new_sk = hkdf_derive_key(sk, salt, counter)?;
    Ok(Arc::new(new_sk))
}
