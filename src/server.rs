use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;

use crate::constants::*;
use crate::crypto::*;

async fn process_message(message: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut new_message = message.to_vec();
    new_message.extend_from_slice(" ;)".as_bytes());

    Ok(new_message)

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
                    println!("Received: {}", String::from_utf8_lossy(&buffer[..n]));
                    
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
