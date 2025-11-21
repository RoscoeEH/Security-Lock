use hex::encode;
use rand::Rng;
use std::error::Error;
use std::fs::{File, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::constants::*;

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
    random_bytes(NONCE_SIZE)
}

pub fn get_salt() -> Vec<u8> {
    random_bytes(SALT_SIZE)
}

// Print function for debugging
pub fn get_hex_string(data: &[u8]) -> String {
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
    key_data: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let expanded = expand_tilde(&key_path);

    if let Some(parent) = expanded.parent() {
        create_dir_all(parent)?;
    }

    let mut file = File::create(&expanded)?;
    file.write_all(key_data)?;
    file.flush()?;

    Ok(())
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs_next::home_dir() {
            return home.join(stripped);
        }
    }
    PathBuf::from(path)
}

pub fn set_status(new_status: u8, status: &Arc<AtomicU8>) {
    status.store(new_status, Ordering::SeqCst);
}

pub fn get_status(status: &Arc<AtomicU8>) -> u8 {
    status.load(Ordering::SeqCst)
}
