use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::constants::*;
use crate::crypto::*;
use crate::key_management::*;

#[allow(unused_imports)] // get_hex_string is sometimes used in debugging
use crate::utils::*;

async fn process_message(
    message: &[u8],
    counter: u32,
    key: &[u8],
    status: &Arc<AtomicU8>,
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

    let mut to_sign = message[3..].to_vec();
    to_sign.push(get_status(status)); // Add status before signing

    if magic != "CHG".as_bytes() {
        return Err("Bad Magic.".into());
    }
    // Check message_num PLACEHOLDER
    if message_num != counter {
        return Err("Bad message number.".into());
    }

    // Placeholder before the deriving of a session key
    let sig = hmac_sign(&to_sign, key)?;

    let mut result = Vec::<u8>::new();
    result.extend_from_slice("RSP".as_bytes());
    result.extend_from_slice(&to_sign);
    result.extend_from_slice(&sig);

    Ok(result)
}

async fn key_agreement(
    mut socket: TcpStream,
    dk: &[u8],
    status: Arc<AtomicU8>,
) -> Result<(TcpStream, Arc<Vec<u8>>), Box<dyn Error + Send + Sync>> {
    // Get initial message
    let mut key_init_message = vec![0; 2048];
    let n = match socket.read(&mut key_init_message).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Error while message: {}", e);
            return Err("Halted due to key agreement error".into());
        }
    };

    // determine sk
    let mut sk = Vec::<u8>::new();
    if n > 0 {
        println!("Recieved key agreement message");

        // check magic
        let magic = &key_init_message[..3];
        if magic != "KAC".as_bytes() {
            return Err("Bad key agreement magic.".into());
        }
        let protected_ss = &key_init_message[3..1091];
        let ss = key_decap(dk, protected_ss)?;
        let salt = &key_init_message[1091..1107];
        sk = hkdf_derive_key(&ss, &salt, 0)?;

        // Send back response
        let key_agreement_challenge = &key_init_message[1107..1139];
        let sig = hmac_sign(&key_agreement_challenge, &sk)?;

        let mut response = Vec::<u8>::new();
        response.extend_from_slice("KAR".as_bytes());
        response.extend_from_slice(&key_agreement_challenge);
        response.extend_from_slice(&sig);

        socket.write_all(&response).await?
    }
    set_status(STATUS_ACTIVE, &status);

    Ok((socket, Arc::new(sk)))
}

async fn challenge_response_loop(
    mut socket: TcpStream,
    mut key: Arc<Vec<u8>>,
    addr: String,
    status: Arc<AtomicU8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut counter: u32 = 0;
    let mut sk_counter: u64 = 1;
    loop {
        let mut buffer = [0; 1024];
        match socket.read(&mut buffer).await {
            Ok(n) if n > 0 => {
                if cfg!(debug_assertions) {
                    println!("Received challenge number: {}", counter);
                }
                match process_message(&buffer[..n], counter, &key, &status).await {
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
        // renew sk at limit
        if counter >= SK_USE_LIMIT {
            // New salt is first 16 random bytes of last message
            let salt = &buffer[3..19];
            key = renew_sk(key.as_slice(), &salt, sk_counter)?;
            sk_counter += 1;
            counter = 0;
        }
    }
    Ok(())
}

pub async fn start_server(
    ip_addr: String,
    key_path: String,
    status: Arc<AtomicU8>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind(ip_addr).await?;
    println!("Server running on localhost:8080");

    let dk = get_decap_key(key_path)?;

    println!("Server ready");

    loop {
        let (socket, addr) = listener.accept().await?;
        println!("New connection: {}", addr);

        let status_clone = Arc::clone(&status);

        // Init key outside the loop, will replace with SK derivation.
        let (socket, key) = key_agreement(socket, &dk, status_clone.clone()).await?;

        let key_clone = Arc::clone(&key);

        tokio::spawn(async move {
            if let Err(e) =
                challenge_response_loop(socket, key_clone, addr.to_string(), status_clone).await
            {
                eprintln!("Error handling connection from {}: {}", addr, e);
            }
        });
    }
}
