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

fn verify_response(response: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if response.len() < 71 {
        return Err("Response is too short".into());
    }

    let magic = &response[..3];

    let response_num_bytes = &response[3..7];
    let response_num = u32::from_le_bytes(response_num_bytes.try_into().map_err(|_| "Invalid slice length")?);

    let content = &response[3..39];
    let sig = &response[39..];

    if magic != "RSP".as_bytes() {
        return Err("Bad Magic.".into());
    }
    // Check message_num PLACEHOLDER
    if response_num != 16 {
        return Err("Bad message number.".into());
    }

    // Placeholder before the deriving of a session key
    let key = get_key()?;
    hmac_verify(content, &key, sig)?;

    Ok(())

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
    println!("Sent");
    print_hex(&message);

    let mut buffer = vec![0; 1024];
    let n = stream.read(&mut buffer).await?;
    if n > 0 {
        println!("Received");
        print_hex(&buffer[..n]);
        match verify_response(&buffer[..n]) {
            Ok(()) => println!("Valid response."),
            Err(_) => println!("Invalid response.")
        }
    }

    println!("Closing connection...");
    sleep(Duration::from_secs(2)).await;
    
    Ok(())
}
