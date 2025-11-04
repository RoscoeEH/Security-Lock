use hex::encode;
use rand::rngs::OsRng;
use rand::RngCore;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};

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
