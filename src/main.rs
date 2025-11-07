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
        cli::Command::Server(args) => {
            server::start_server(args.ip_addr, args.key_path).await?;
        }
        cli::Command::Client(args) => {
            if let Err(e) = client::start_client(args.ip_addr, args.key_path).await {
                eprintln!("Client encountered an error: {}", e);
            }
            utils::run_shutdown()?;
        }
    }

    Ok(())
}
