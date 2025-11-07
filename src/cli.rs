use crate::constants::*;
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "seclock", version, about = "Device locking exchange")]
/// The top-level command to execute.
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    Server(ClArgs),
    Client(ClArgs),
}

#[derive(Args, Clone)]
pub struct ClArgs {
    #[arg(short = 'i', long = "ip", default_value_t = String::from(DEFAULT_IP_ADDRESS))]
    pub ip_addr: String,

    #[arg(short = 'k', long = "key", default_value_t = String::from(DEFAULT_KEY_FILE))]
    pub key_path: String,
}
