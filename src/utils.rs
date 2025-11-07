use hex::encode;
use rand::RngCore;
use rand::rngs::OsRng;
use rpassword::read_password;
use std::fs::File;
use std::io::{self, Read};
use std::process::Command;

use crate::constants::*;
use crate::crypto::*;

// Returns 256 random bits
pub fn get_random_bits() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut message = vec![0u8; MESSAGE_SIZE];
    OsRng.try_fill_bytes(&mut message)?;
    Ok(message)
}

// Reads the preshared key file
pub fn get_psk(key_path: String) -> io::Result<Vec<u8>> {
    let mut file = File::open(key_path)?;

    // TODO check if the file in encrypted and get kek if needed

    let mut key = Vec::new();
    file.read_to_end(&mut key)?;
    Ok(key)
}

pub fn get_kek(salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    println!("Enter password: ");
    let password = read_password()?;

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
