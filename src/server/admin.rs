use tokio::sync::broadcast;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::net::SocketAddr;

use super::state::{ServerState, save_disk_state};
use crate::protocol::WireMessage;

pub async fn handle_admin_command(
    command: String,
    target: String,
    my_username: &str,
    my_fp: &str,
    addr: SocketAddr,
    state: &Arc<ServerState>,
    tx: &broadcast::Sender<WireMessage>,
    log_event: impl Fn(SocketAddr, &str, &str, String),
) {
    if state.admins.contains_key(my_fp) {
        let now = Instant::now();
        let mut allowed = true;
        if let Some(mut last) = state.admin_rate_limit.get_mut(my_fp) {
            if last.elapsed() < Duration::from_secs(2) {
                log_event(addr, "⚠️", "RATE", "Admin rate limit hit".into());
                allowed = false;
            } else {
                *last = now;
            }
        } else {
            state.admin_rate_limit.insert(my_fp.to_string(), now);
        }

        if allowed {
            log_event(addr, "⚡", "ADMIN", format!("{} executed {} on {}", my_username, command, target));

            if command == "kick" {
                let _ = tx.send(WireMessage::System { content: format!("{} was kicked by admin.", target) });
                let _ = tx.send(WireMessage::AdminCommand { command, target });
            } else if command == "ban" {
                state.blacklist.insert(target.clone(), "Banned by Admin".to_string());
                save_disk_state(state).await;
                let _ = tx.send(WireMessage::System { content: format!("{} was BANNED by admin.", target) });
                let _ = tx.send(WireMessage::AdminCommand { command: "kick".to_string(), target });
            }
        }
    } else {
        log_event(addr, "⚠️", "AUTH", format!("{} tried admin command but is not admin", my_username));
    }
}
