use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::protocol::WireMessage;

pub struct UserSession {
    pub username: String,
    pub group: String,
}

pub struct StoredMessage {
    pub msg: WireMessage,
    pub expires_at: Option<Instant>,
}

pub type Mailbox = DashMap<String, Vec<StoredMessage>>;
pub type Blacklist = DashMap<String, String>;
pub type Admins = DashMap<String, bool>;

pub struct ServerState {
    pub users: Arc<DashMap<String, UserSession>>,
    pub mailbox: Arc<Mailbox>,
    pub blacklist: Arc<Blacklist>,
    pub admins: Arc<Admins>,
    pub admin_rate_limit: Arc<DashMap<String, Instant>>,
    pub connection_attempts: Arc<DashMap<IpAddr, (u32, Instant)>>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct DiskState {
    pub blacklist: Vec<(String, String)>,
    pub admins: Vec<(String, bool)>,
}

pub async fn load_disk_state() -> DiskState {
    tokio::task::spawn_blocking(|| {
        if let Ok(file) = File::open("server_state.json") {
            let reader = std::io::BufReader::new(file);
            serde_json::from_reader(reader).unwrap_or_default()
        } else {
            DiskState::default()
        }
    })
    .await
    .unwrap_or_default()
}

pub async fn save_disk_state(state: &ServerState) {
    let disk_state = DiskState {
        blacklist: state
            .blacklist
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect(),
        admins: state
            .admins
            .iter()
            .map(|r| (r.key().clone(), *r.value()))
            .collect(),
    };
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(file) = File::create("server_state.json") {
            let writer = std::io::BufWriter::new(file);
            let _ = serde_json::to_writer_pretty(writer, &disk_state);
        }
    })
    .await;
}
