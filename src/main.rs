use clap::{Parser, Subcommand};
use anyhow::Result;

use isotope::*;

#[derive(Parser)]
#[command(name = "isotope")]
#[command(about = "ISOTOPE: Post-Quantum Secure Chat over Tor", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start in Server (Listener) Mode
    Server {
        #[arg(short, long, default_value_t = 7878)]
        port: u16,
        #[arg(long, default_value = DEFAULT_ID_FILE)]
        identity: String,
    },
    /// Start in Client (Connect) Mode
    Client {
        #[arg(short, long)]
        address: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        peer_fingerprint: String,
        #[arg(long, default_value = DEFAULT_SOCKS_PROXY)]
        proxy: String,
        #[arg(long, default_value = DEFAULT_ID_FILE)]
        identity: String,
        #[arg(short, long, default_value = "public")]
        group: String,
        
        // Temp Flag for Auto-Generation
        #[arg(long)]
        temp: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Server { port, identity } => {
            server::run(port, identity).await?;
        }
        Commands::Client { address, username, peer_fingerprint, proxy, identity, group, temp } => {
            client::run(address, username, peer_fingerprint, proxy, identity, group, temp).await?;
        }
    }

    Ok(())
}
