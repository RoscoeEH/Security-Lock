use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, sleep, timeout};

use crate::constants::*;
use crate::crypto::*;
use crate::utils::*;

fn get_challenge(counter: u32) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Magic (12 bytes) | message number (4 bytes) | message (32 bytes)

    let mut challenge = Vec::<u8>::new();
    // Add magic bytes
    challenge.extend_from_slice("CHG".as_bytes());
    // Add challenge number
    let num = counter.to_le_bytes();
    challenge.extend_from_slice(&num);
    // Add random message
    let message = get_message()?;
    challenge.extend_from_slice(&message);

    Ok(challenge)
}

fn verify_response(
    response: &[u8],
    og_message: &[u8],
    counter: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    let key = get_key()?;
    hmac_verify(content, &key, sig)?;

    Ok(())
}

pub async fn start_client() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_addr = ADDRESS;

    let mut counter: u32 = 0;

    let mut stream = match TcpStream::connect(server_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Failed to connect to server: {}", e);
            return Err(Box::new(e));
        }
    };
    println!("Connected to server at {}", server_addr);

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
        println!("Sent: {}", counter);

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
            println!("Received");

            match verify_response(&buffer[..n], &message, counter) {
                Ok(()) => println!("Valid response."),
                Err(_) => {
                    println!("Invalid response.");
                    break;
                }
            }
        }
        counter += 1;
        sleep(Duration::from_millis(MESSAGE_DELAY)).await;
    }

    println!("Closing connection...");

    Ok(())
}
