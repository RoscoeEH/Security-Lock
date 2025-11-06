use hex::encode;
use rand::RngCore;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::{self, Read};
use std::process::Command;

use crate::constants::*;

// Returns 256 random bits
pub fn get_message() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut message = vec![0u8; MESSAGE_SIZE];
    OsRng.try_fill_bytes(&mut message)?;
    Ok(message)
}

pub fn get_key() -> io::Result<Vec<u8>> {
    let mut file = File::open(HMAC_KEY_FILE)?;
    let mut key = Vec::new();
    file.read_to_end(&mut key)?;
    Ok(key)
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
