use hex::encode;
use rand::Rng;
use rpassword::read_password;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::Command;

use crate::constants::*;
use crate::crypto::*;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill(&mut buf[..]);
    buf
}

// Returns 256 random bits
pub fn get_message() -> Vec<u8> {
    random_bytes(MESSAGE_SIZE)
}

pub fn get_nonce() -> Vec<u8> {
    random_bytes(12)
}

pub fn get_salt() -> Vec<u8> {
    random_bytes(16)
}

// Reads the preshared key file
pub fn get_psk(key_path: String) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut file = File::open(&key_path)?;

    let mut key_bytes = Vec::new();
    file.read_to_end(&mut key_bytes)?;

    let psk = match key_bytes.len() {
        // Key is plaintext, raw 256 bits
        32 => {
            // Prompt to encrypt the key for the future
            print!("Do you want to encrypt your PSK for security? [y/N]: ");
            io::stdout().flush()?;

            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if answer.trim().eq_ignore_ascii_case("n") {
                println!("Key will remain plaintext. This is not recomended.");
            } else {
                encrypt_key_file(key_path.clone(), &key_bytes)?;
            }
            key_bytes
        }
        // Key is encrypted, has header, nonce, signature, etc...
        79 => decrypt_key_file(&key_bytes)?,
        _ => {
            return Err("Unrecognized PSK format.".into());
        }
    };

    Ok(psk)
}

fn encrypt_key_file(
    key_path: String,
    key_bytes: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let salt = get_salt();
    let kek = get_kek(&salt)?;
    let nonce = get_nonce();
    let ciphertext = encrypt(key_bytes, &kek, &nonce)?;

    // Built new key file
    let mut new_key_bytes = Vec::<u8>::new();
    new_key_bytes.extend_from_slice("KEY".as_bytes());
    new_key_bytes.extend_from_slice(&ciphertext);
    new_key_bytes.extend_from_slice(&nonce);
    new_key_bytes.extend_from_slice(&salt);

    overwrite_key_file(key_path, &new_key_bytes)?;
    println!("Key file is encrypted.");

    Ok(())
}

fn decrypt_key_file(key_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Encrypted key format -> "KEY" (3 bytes) | Ciphertext (48 bytes) | Nonce (12 bytes) | KEK salt (16 bytes)
    let magic = &key_bytes[..3];
    let ciphertext = &key_bytes[3..51];
    let nonce = &key_bytes[51..63];
    let salt = &key_bytes[63..79];

    // Verify magic
    if magic != "KEY".as_bytes() {
        return Err("Bad PSK magic.".into());
    }

    // Derive kek
    let kek = get_kek(salt)?;
    let plaintext_key = match decrypt(ciphertext, &kek, nonce) {
        Ok(key) => key,
        Err(_) => return Err("PSK decryption failed.".into()),
    };

    Ok(plaintext_key)
}

// TODO read password twice on first entry to avoid the wrong password
fn get_kek(salt: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    println!("Enter password: ");
    // puts in a password automatically in dev mode for testing
    let password = match cfg!(debug_assertions) {
        true => {
            println!("[DEV MODE] Using default password");
            String::from("password")
        }
        false => read_password()?,
    };

    let kek = argon2_derive_key(password, salt)?;

    Ok(kek)
}

// Print function for debugging
pub fn print_hex(data: &[u8]) -> String {
    let hex_string = encode(data);
    hex_string
}

pub fn run_shutdown() -> std::io::Result<()> {
    if cfg!(debug_assertions) {
        println!("[DEV MODE] Would shutdown system");
        Ok(())
    } else {
        let status = Command::new(DISCONNECT_PROGRAM)
            .arg(DISCONNECT_ARG)
            .status()?;

        if status.success() {
            println!("System is shutting down...");
            Ok(())
        } else {
            eprintln!("Failed to execute shutdown: {:?}", status);
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "shutdown failed",
            ))
        }
    }
}

pub fn overwrite_key_file(
    key_path: String,
    encrypted_key: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut file = File::create(key_path)?;

    file.write_all(encrypted_key)?;
    file.flush()?; // ensure data is fully written

    Ok(())
}
