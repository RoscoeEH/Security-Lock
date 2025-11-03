use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::time::Duration;
use tokio::time::sleep;

use crate::constants::*;
use crate::crypto::*;
use crate::utils::*;

// placeholder
static COUNTER: u32 = 16;

fn get_challenge() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Magic (12 bytes) | message number (4 bytes) | message (32 bytes)
    
    let mut challenge = Vec::<u8>::new();
    // Add magic bytes
    challenge.extend_from_slice("CHG".as_bytes());
    // Add challenge number
    let num = COUNTER.to_le_bytes();
    challenge.extend_from_slice(&num);
    // Add random message
    let message = get_message()?;
    challenge.extend_from_slice(&message);
    
    Ok(challenge)
}

fn verify_response(response: &[u8]) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    Ok(true)
}

pub async fn start_client() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_addr = ADDRESS;

    let mut stream = match TcpStream::connect(server_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Failed to connect to server: {}", e);
            return Err(Box::new(e));
        }
    };
    
    println!("Connected to server at {}", server_addr);

    let message = get_challenge()?;
    stream.write_all(&message).await?;
    println!("Sent: {}", String::from_utf8_lossy(&message));

    let mut buffer = vec![0; 1024];
    let n = stream.read(&mut buffer).await?;
    if n > 0 {
        let response = String::from_utf8_lossy(&buffer[..n]);
        println!("Received: {}", response);
    }

    println!("Closing connection...");
    sleep(Duration::from_secs(2)).await;
    
    Ok(())
}
