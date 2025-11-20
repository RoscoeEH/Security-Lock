use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep, timeout};

use crate::constants::*;
use crate::crypto::*;
use crate::key_management::*;
use crate::utils::*;

static SK_COUNTER: AtomicU64 = AtomicU64::new(0);

fn get_challenge(counter: u32) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    // Magic (3 bytes) | message number (4 bytes) | message (32 bytes)

    let mut challenge = Vec::<u8>::new();
    // Add magic bytes
    challenge.extend_from_slice("CHG".as_bytes());
    // Add challenge number
    let num = counter.to_le_bytes();
    challenge.extend_from_slice(&num);
    // Add random message
    let message = get_message();
    challenge.extend_from_slice(&message);

    Ok(challenge)
}

fn verify_response(
    response: &[u8],
    og_message: &[u8],
    counter: u32,
    key: &[u8],
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if response.len() < 71 {
        return Err("Response is too short".into());
    }

    let magic = &response[..3];

    let response_num_bytes = &response[3..7];
    let response_num = u32::from_le_bytes(
        response_num_bytes
            .try_into()
            .map_err(|_| "Invalid slice length")?,
    );

    let content = &response[3..39];
    let sig = &response[39..];

    if magic != "RSP".as_bytes() {
        return Err("Bad Magic.".into());
    }
    // Check message_num
    if response_num != counter {
        return Err("Bad message number.".into());
    }

    let og_message_content = &og_message[3..];
    if content != og_message_content {
        return Err("Bad message.".into());
    }

    // Placeholder before the deriving of a session key
    hmac_verify(content, &key, sig)?;

    Ok(())
}

async fn key_agreement(
    mut stream: TcpStream,
    key_path: String,
) -> Result<(TcpStream, Arc<Vec<u8>>), Box<dyn Error + Send + Sync>> {
    // Read encap key and get shared secret
    let ek = get_encap_key(key_path)?;
    let (protected_ss, ss) = key_encap(&ek)?;

    // Get sek from hkdf
    let salt = get_salt();
    let sek = hkdf_derive_key(&ss, &salt, &SK_COUNTER)?;

    // Generate key agreement message
    // format is: "KAC" (3 bytes) | ss encrypted (1088 bytes) | salt (16 bytes) | message (32 bytes)
    let mut message = Vec::<u8>::new();
    message.extend_from_slice("KAC".as_bytes());
    message.extend_from_slice(&protected_ss);
    message.extend_from_slice(&salt);
    let key_agreement_challenge = get_message();
    message.extend_from_slice(&key_agreement_challenge);

    // Get response
    if let Err(e) = stream.write_all(&message).await {
        eprintln!("Failed to write response: {}", e);
    }
    println!("Initiated key agreement");

    // Check response
    let mut response = vec![0; 1024];
    let n = match timeout(
        Duration::from_millis(TIMEOUT_WINDOW),
        stream.read(&mut response),
    )
    .await
    {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            eprintln!("Error while reading response: {}", e);
            return Err("Halted due to key agreement error".into());
        }
        Err(_) => {
            return Err("Timeout while reading key agreement response".into());
        }
    };

    if n > 0 {
        println!("Received key agreement response");

        // check magic
        let magic = &response[..3];
        if magic != "KAR".as_bytes() {
            return Err("Bad key agreement magic.".into());
        }

        // check response was not altered
        let response_challenge = &response[3..35];
        if response_challenge != key_agreement_challenge {
            return Err("Incorrect message recieved during key agreement.".into());
        }

        // verify signature
        let key_agreement_sig = &response[35..67];
        hmac_verify(response_challenge, &sek, key_agreement_sig)?;
    }

    println!("Key agreement succeeded.");

    Ok((stream, Arc::new(sek)))
}

async fn challenge_response_loop(
    mut stream: TcpStream,
    mut key: Arc<Vec<u8>>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut counter: u32 = 0;
    loop {
        let message = get_challenge(counter)?;
        if let Err(e) = stream.write_all(&message).await {
            if e.kind() == std::io::ErrorKind::BrokenPipe
                || e.kind() == std::io::ErrorKind::ConnectionReset
            {
                eprintln!("Server disconnected. Closing client...");
                break;
            } else {
                return Err(Box::new(e));
            }
        }
        if cfg!(debug_assertions) {
            println!("Sent challenge number: {}", counter);
        }

        let mut buffer = vec![0; 1024];
        let n = match timeout(
            Duration::from_millis(TIMEOUT_WINDOW),
            stream.read(&mut buffer),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                eprintln!("Error while reading response: {}", e);
                break;
            }
            Err(_) => {
                eprintln!("Timeout while reading response");
                break;
            }
        };
        if n > 0 {
            if cfg!(debug_assertions) {
                println!("Received response");
            }

            match verify_response(&buffer[..n], &message, counter, &key) {
                Ok(()) => {
                    if cfg!(debug_assertions) {
                        println!("Response validated");
                    }
                }
                Err(_) => {
                    println!("Invalid response.");
                    break;
                }
            }
        }

        counter += 1;
        // renew sek at limit
        if counter >= SEK_USE_LIMIT {
            // New salt is first 16 random bytes of last message
            let salt = &buffer[3..19];
            key = renew_sek(key.as_slice(), &salt, &SK_COUNTER)?;
            counter = 0;
        }
        sleep(Duration::from_millis(MESSAGE_DELAY)).await;
    }
    Ok(())
}

pub async fn start_client(
    ip_addr: String,
    key_path: String,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server_addr = ip_addr.as_str();

    let stream = match TcpStream::connect(server_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Failed to connect to server: {}", e);
            return Err(Box::new(e));
        }
    };
    println!("Connected to server at {}", server_addr);

    // Init key outside the loop, will replace with SEK derivation.
    let (stream, key) = key_agreement(stream, key_path).await?;

    challenge_response_loop(stream, key).await?;

    println!("Closing connection...");

    Ok(())
}
