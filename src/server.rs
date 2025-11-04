use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;

use crate::constants::*;
use crate::crypto::*;
use crate::utils::*;

async fn process_message(message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    if message.len() < 39 {
        return Err("Message is too short".into());
    }

    let magic = &message[..3];

    let message_num_bytes = &message[3..7];
    let message_num = u32::from_le_bytes(message_num_bytes.try_into().map_err(|_| "Invalid slice length")?);

    let to_sign = &message[3..];

    if magic != "CHG".as_bytes() {
        return Err("Bad Magic.".into());
    }
    // Check message_num PLACEHOLDER
    if message_num != 16 {
        return Err("Bad message number.".into());
    }

    // Placeholder before the deriving of a session key
    let key = get_key()?;
    let sig = hmac_sign(to_sign, &key)?;


    let mut result = Vec::<u8>::new();
    result.extend_from_slice("RSP".as_bytes());
    result.extend_from_slice(to_sign);
    result.extend_from_slice(&sig);
    
    Ok(result)
}



pub async fn start_server() -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(ADDRESS).await?;
    println!("Server running on localhost:8080");

    loop {
        let (mut socket, addr) = listener.accept().await?;
        println!("New connection: {}", addr);

        tokio::spawn(async move {
            let mut buffer = [0; 1024];
            match socket.read(&mut buffer).await {
                Ok(n) if n > 0 => {
                    println!("Received");
                    print_hex(&buffer[..n]);
                    
                    match process_message(&buffer[..n]).await {
                        Ok(response) => {
                            if let Err(e) = socket.write_all(&response).await {
                                eprintln!("Failed to write response: {}", e);
                            }
                        }
                        Err(e) => eprintln!("Failed to process message: {}", e),
                    }
                }
                Ok(_) => eprintln!("Connection closed by {}", addr),
                Err(e) => eprintln!("Failed to read from socket: {}", e),
            }
        });
    }
}
