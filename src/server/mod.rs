pub mod state;
pub mod handshake;
pub mod router;
pub mod admin;

use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::time::Duration;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use anyhow::Result;
use tracing::{warn, error};
use crossterm::style::Stylize;

use crate::crypto::Identity;
use crate::protocol::WireMessage;
use state::{ServerState, load_disk_state};
use router::handle_client;

fn print_banner(port: u16, fingerprint: &str) {
    print!("\x1B[2J\x1B[1;1H"); 
    println!("{}", r#"
██╗███████╗ ██████╗ ████████╗ ██████╗ ██████╗ ███████╗
██║██╔════╝██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝
██║███████╗██║   ██║   ██║   ██║   ██║██████╔╝█████╗  
██║╚════██║██║   ██║   ██║   ██║   ██║██╔═══╝ ██╔══╝  
██║███████║╚██████╔╝   ██║   ╚██████╔╝██║     ███████╗
╚═╝╚══════╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚══════╝
"#.blue().bold());
    
    println!("   {} {}", "► VERSION:".dim(), "4.0.0 (MILITARY-GRADE)".cyan());
    println!("   {} {}", "► LISTEN :".dim(), format!("127.0.0.1:{}", port).yellow());
    println!("   {} {}", "► SERVER :".dim(), fingerprint.green());
    println!("   {} {}", "► STATUS :".dim(), "ONLINE & SECURE".green().bold());
    println!("{}", "──────────────────────────────────────────────────────────────".dim());
    println!();
}

pub async fn run(port: u16, identity_path: String) -> Result<()> {
    let id = if std::path::Path::new(&identity_path).exists() {
        println!("Enter password for server identity:");
        let pass = rpassword::read_password()?;
        Identity::load(&identity_path, &pass)?
    } else {
        println!("Creating new server identity...");
        println!("Set password:");
        let pass = rpassword::read_password()?;
        println!("Confirm password:");
        let confirm = rpassword::read_password()?;
        if pass != confirm {
            anyhow::bail!("Passwords do not match");
        }
        println!("Set duress password (optional, press enter to skip/use same):");
        let duress = rpassword::read_password()?;
        let duress = if duress.is_empty() { &pass } else { &duress };
        
        Identity::setup_dual(&identity_path, &pass, duress)?;
        Identity::load(&identity_path, &pass)?
    };

    let fp = id.fingerprint();
    print_banner(port, &fp);

    let disk = load_disk_state().await;
    let blacklist_map = DashMap::new();
    for (k, v) in disk.blacklist { blacklist_map.insert(k, v); }
    let admin_map = DashMap::new();
    for (k, v) in disk.admins { admin_map.insert(k, v); }

    let state = Arc::new(ServerState {
        users: Arc::new(DashMap::new()),
        mailbox: Arc::new(DashMap::new()),
        blacklist: Arc::new(blacklist_map),
        admins: Arc::new(admin_map),
        admin_rate_limit: Arc::new(DashMap::new()),
        connection_attempts: Arc::new(DashMap::new()),
    });
    
    state.admins.insert(fp.clone(), true);

    let (tx, _rx) = broadcast::channel::<WireMessage>(100);
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    let id = Arc::new(id);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let ip = addr.ip();
                let mut allowed = true;
                let mut attempts = state.connection_attempts.entry(ip).or_insert((0, Instant::now()));
                if attempts.1.elapsed() > Duration::from_secs(60) {
                    *attempts = (1, Instant::now());
                } else {
                    attempts.0 += 1;
                    if attempts.0 > 20 { 
                        allowed = false;
                    }
                }
                drop(attempts);

                if !allowed {
                    warn!("{} | ⚠️ Throttled (DoS Protection)", addr);
                    continue;
                }

                let id_clone = id.clone();
                let tx_clone = tx.clone();
                let rx_clone = tx.subscribe();
                let state_clone = state.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, id_clone, tx_clone, rx_clone, state_clone, addr).await {
                        if !e.to_string().contains("closed normally") {
                             warn!("{} | ❌ Error: {}", addr, e);
                        }
                    }
                });
            }
            Err(e) => error!("Listener Accept Error: {}", e),
        }
    }
}
