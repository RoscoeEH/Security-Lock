pub mod cli;
pub mod client;
pub mod constants;
pub mod crypto;
pub mod server;
pub mod utils;

use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = cli::Cli::parse();

    match cli.command {
        cli::Command::Server => {
            server::start_server().await?;
        }
        cli::Command::Client => {
            if let Err(e) = client::start_client().await {
                eprintln!("Client encountered an error: {}", e);
            }
            utils::run_shutdown()?;
        }
    }

    Ok(())
}
