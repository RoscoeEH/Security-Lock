use hex::encode;
use rand::RngCore;
use rand::rngs::OsRng;
use rpassword::read_password;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::Command;

use crate::constants::*;
use crate::crypto::*;

// Returns 256 random bits
pub fn get_random_bits() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut message = vec![0u8; MESSAGE_SIZE];
    OsRng.try_fill_bytes(&mut message)?;
    Ok(message)
}

pub fn get_nonce() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut nonce = vec![0u8; 12];
    OsRng.try_fill_bytes(&mut nonce)?;
    Ok(nonce)
}

pub fn get_salt() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut salt = vec![0u8; 16];
    OsRng.try_fill_bytes(&mut salt)?;
    Ok(salt)
}

// Reads the preshared key file
pub fn get_psk(key_path: String) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut file = File::open(&key_path)?;

    let mut key_file = Vec::new();
    file.read_to_end(&mut key_file)?;

    let psk = match key_file.len() {
        // Key is plaintext
        32 => {
            // Prompt to encrypt the key for the future
            print!("Do you want to encrypt your PSK for security? [y/N]: ");
            io::stdout().flush()?;

            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if !answer.trim().eq_ignore_ascii_case("y") {
                println!("Key will remain plaintext. This is not recomended.");
            }
            // Encrypt the key file
            else {
                let salt = get_salt()?;
                let kek = get_kek(&salt)?;
                let nonce = get_nonce()?;
                let ciphertext = encrypt(&key_file, &kek, &nonce)?;

                // Built new key file
                let mut new_key_file = Vec::<u8>::new();
                new_key_file.extend_from_slice("KEY".as_bytes());
                new_key_file.extend_from_slice(&ciphertext);
                new_key_file.extend_from_slice(&nonce);
                new_key_file.extend_from_slice(&salt);

                overwrite_key_file(key_path, &new_key_file)?;
                println!("Key file is encrypted.")
            }
            key_file
        }
        // Key in encrypted format -> "KEY" (3 bytes) | Ciphertext (48 bytes) | Nonce (12 bytes) | KEK salt (16 bytes)
        79 => {
            let magic = &key_file[..3];
            let ciphertext = &key_file[3..51];
            let nonce = &key_file[51..63];
            let salt = &key_file[63..79];

            // Verify magic
            if magic != "KEY".as_bytes() {
                return Err("Bad PSK magic.".into());
            }

            // Derive kek
            let kek = get_kek(salt)?;
            let plaintext_key = match decrypt(ciphertext, &kek, nonce) {
                Ok(key) => key,
                Err(_) => return Err("KEK decryption failed.".into()),
            };

            plaintext_key
        }
        _ => {
            return Err("Unrecognized PSK format.".into());
        }
    };

    Ok(psk)
}

pub fn get_kek(salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    println!("Enter password: ");
    // puts in a password automatically in dev mode for testing
    let password = match cfg!(debug_assertions) {
        true => {
            println!("[DEV MODE] Using default password");
            String::from("password")
        }
        false => read_password()?,
    };

    let kek = derive_key(password, salt)?;

    Ok(kek)
}

// Print function for debugging
pub fn print_hex(data: &[u8]) {
    let hex_string = encode(data);
    println!("{}", hex_string);
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = File::create(key_path)?;

    file.write_all(encrypted_key)?;
    file.flush()?; // ensure data is fully written

    Ok(())
}
