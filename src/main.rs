use clap::Parser;
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;

pub mod cli;
pub mod client;
pub mod constants;
pub mod crypto;
pub mod key_management;
pub mod server;
pub mod utils;

use crate::cli::*;
use crate::client::*;
use crate::constants::*;
use crate::key_management::*;
use crate::server::*;
use crate::utils::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let cli = Cli::parse();

    // Maintains status over all connections
    let status = Arc::new(AtomicU8::new(STATUS_INITIAL));

    match cli.command {
        Command::Server(args) => {
            let result = start_server(args.ip_addr, args.key_path, Arc::clone(&status)).await;
            if let Err(_) = result {
                set_status(STATUS_ERROR, &status);
            }
            result?;
        }
        Command::Client(args) => {
            if let Err(e) = start_client(args.ip_addr, args.key_path).await {
                eprintln!("Client encountered an error: {}", e);
            }
            run_shutdown()?;
        }
        Command::KeyGen(args) => generate_user_keypair(args.decap_key_path, args.encap_key_path)?,
    }

    Ok(())
}
