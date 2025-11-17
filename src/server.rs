use std::error::Error;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::crypto::*;
use crate::utils::*;

async fn process_message(
    message: &[u8],
    counter: u32,
    key: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    if message.len() < 39 {
        return Err("Message is too short".into());
    }

    let magic = &message[..3];

    let message_num_bytes = &message[3..7];
    let message_num = u32::from_le_bytes(
        message_num_bytes
            .try_into()
            .map_err(|_| "Invalid slice length")?,
    );

    let to_sign = &message[3..];

    if magic != "CHG".as_bytes() {
        return Err("Bad Magic.".into());
    }
    // Check message_num PLACEHOLDER
    if message_num != counter {
        return Err("Bad message number.".into());
    }

    // Placeholder before the deriving of a session key
    let sig = hmac_sign(to_sign, key)?;

    let mut result = Vec::<u8>::new();
    result.extend_from_slice("RSP".as_bytes());
    result.extend_from_slice(to_sign);
    result.extend_from_slice(&sig);

    Ok(result)
}

async fn key_agreement(
    mut socket: TcpStream,
    psk: &[u8],
) -> Result<(TcpStream, Arc<Vec<u8>>), Box<dyn Error + Send + Sync>> {
    // Get initial message
    let mut key_init_message = vec![0; 1024];
    let n = match socket.read(&mut key_init_message).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Error while message: {}", e);
            return Err("Halted due to key agreement error".into());
        }
    };
    let mut sek = Vec::<u8>::new();
    if n > 0 {
        println!("Recieved key agreement message");

        // check magic
        let magic = &key_init_message[..3];
        if magic != "KAC".as_bytes() {
            return Err("Bad key agreement magic.".into());
        }
        let encrypted_sek = &key_init_message[3..51];
        let nonce = &key_init_message[51..63];
        sek = decrypt(&encrypted_sek, &psk, &nonce)?;

        // Send back response
        let key_agreement_challenge = &key_init_message[63..95];
        let sig = hmac_sign(&key_agreement_challenge, &sek)?;

        let mut response = Vec::<u8>::new();
        response.extend_from_slice("KAR".as_bytes());
        response.extend_from_slice(&key_agreement_challenge);
        response.extend_from_slice(&sig);

        socket.write_all(&response).await?
    }

    Ok((socket, Arc::new(sek)))
}

async fn challenge_response_loop(
    mut socket: TcpStream,
    key: &Arc<Vec<u8>>,
    addr: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut counter: u32 = 0;
    loop {
        let mut buffer = [0; 1024];
        match socket.read(&mut buffer).await {
            Ok(n) if n > 0 => {
                if cfg!(debug_assertions) {
                    println!("Received challenge number: {}", counter);
                }
                match process_message(&buffer[..n], counter, &key).await {
                    Ok(response) => {
                        if let Err(e) = socket.write_all(&response).await {
                            eprintln!("Failed to write response: {}", e);
                        }
                    }
                    Err(e) => eprintln!("Failed to process message: {}", e),
                }
                if cfg!(debug_assertions) {
                    println!("Sent response");
                }
            }
            Ok(_) => {
                eprintln!("Connection closed by {}", addr);
                break;
            }
            Err(e) => eprintln!("Failed to read from socket: {}", e),
        }
        counter += 1;
    }
    Ok(())
}

pub async fn start_server(
    ip_addr: String,
    key_path: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(ip_addr).await?;
    println!("Server running on localhost:8080");

    let psk = get_psk(key_path)?;

    println!("Server ready");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection: {}", addr);

        // Init key outside the loop, will replace with SEK derivation.
        let (socket, key) = key_agreement(socket, &psk).await?;

        let key_clone = Arc::clone(&key);

        tokio::spawn(async move {
            if let Err(e) = challenge_response_loop(socket, &key_clone, addr.to_string()).await {
                eprintln!("Error handling connection from {}: {}", addr, e);
            }
        });
    }
}
