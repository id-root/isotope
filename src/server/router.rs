use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Instant;
use anyhow::{Result, anyhow};
use chrono::Utc;
use crossterm::style::Stylize;

use crate::crypto::Identity;
use crate::protocol::{IsotopePacket, WireMessage};
use crate::network::{read_packet, write_packet_as_server};
use crate::config::defaults::READ_TIMEOUT_SEC;
use super::state::{ServerState, UserSession, StoredMessage};
use super::handshake::perform_server_handshake;
use super::admin::handle_admin_command;

pub fn log_event(addr: SocketAddr, icon: &str, title: &str, details: String) {
    let time = Utc::now().format("%H:%M:%S").to_string().dim();
    println!("{} {} | {} {:<5} | {}", 
        time, 
        addr.to_string().dim(), 
        icon, 
        title, 
        details
    );
}

pub async fn handle_client(
    mut stream: TcpStream,
    id: Arc<Identity>,
    tx: broadcast::Sender<WireMessage>,
    mut rx: broadcast::Receiver<WireMessage>,
    state: Arc<ServerState>,
    addr: SocketAddr,
) -> Result<()> {
    let (session, fp) = perform_server_handshake(&mut stream, &id, addr).await?;

    let username: String;
    let user_did: String;
    let group: String;
    {
        let wire_buf = timeout(Duration::from_secs(READ_TIMEOUT_SEC), read_packet(&mut stream)).await??;
        let decrypted = session.lock().map_err(|e| anyhow!("Lock poisoned: {}", e))?.decrypt(&wire_buf)?;
        let packet = IsotopePacket::from_bytes(&decrypted)?;

        if let Ok(WireMessage::Join { username: u, did: d, group: g }) = bincode::deserialize(&packet.payload) {
            username = u.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(32)
                .collect();

            if username.is_empty() {
                anyhow::bail!("Invalid username");
            }
            user_did = d;
            group = g;

            if let Some(reason) = state.blacklist.get(&username) {
                log_event(addr, "🚫", "BANNED", format!("{} tried to join (Reason: {})", username, reason.value()));
                anyhow::bail!("User Banned");
            }

            state.users.insert(fp.clone(), UserSession {
                username: username.clone(),
                group: group.clone(),
            });

            log_event(addr, "🟢", "JOINED", format!("{} @ {}", username.clone().bold(), group.clone().cyan()));

            let _ = tx.send(WireMessage::Join {
                username: username.clone(),
                did: user_did.clone(),
                group: group.clone(),
            });
            let _ = tx.send(WireMessage::PeerList { peers: vec![] });

            if let Some((_, stored_msgs)) = state.mailbox.remove(&username) {
                let now = Instant::now();
                let original_count = stored_msgs.len();
                let valid_msgs: Vec<_> = stored_msgs.into_iter()
                    .filter(|sm| sm.expires_at.map_or(true, |exp| exp > now))
                    .collect();

                let expired = original_count - valid_msgs.len();
                if expired > 0 {
                    log_event(addr, "🗑️", "TTL", format!("Discarded {} expired messages", expired));
                }

                log_event(addr, "📬", "MAILBOX", format!("Delivered {} messages to {}", valid_msgs.len(), username));
                for sm in valid_msgs {
                    let data = bincode::serialize(&sm.msg)?;
                    let pkt = IsotopePacket::new(&data)?;
                    let enc = session.lock().map_err(|e| anyhow!("Lock poisoned: {}", e))?.encrypt(&pkt.to_bytes()?)?;
                    write_packet_as_server(&mut stream, &enc).await?;
                }
            }
        } else {
            anyhow::bail!("Expected JOIN");
        }
    }

    let (mut reader, mut writer) = stream.into_split();
    let sess_read = session.clone();
    let sess_write = session.clone();

    let my_fp = fp.clone();
    let my_username = username.clone();
    let my_group = group.clone();
    let tx_inner = tx.clone();
    let state_inner = state.clone();

    tokio::select! {
        _ = async {
            loop {
                let wire_res = timeout(Duration::from_secs(READ_TIMEOUT_SEC), read_packet(&mut reader)).await;
                if wire_res.is_err() { break; }
                let wire_res = wire_res.unwrap();
                if wire_res.is_err() { break; }
                let wire = wire_res.unwrap();

                let res = {
                    let mut lock = match sess_read.lock() { Ok(l) => l, Err(_) => break };
                    lock.decrypt(&wire)
                };
                if let Ok(plain) = res {
                    if let Ok(pkt) = IsotopePacket::from_bytes(&plain) {
                        if let Ok(msg) = bincode::deserialize::<WireMessage>(&pkt.payload) {
                            match msg {
                                WireMessage::Heartbeat => {},
                                WireMessage::Chat { content, .. } => {
                                    let _ = tx_inner.send(WireMessage::Chat {
                                        sender: my_username.clone(), content, timestamp: Utc::now()
                                    });
                                },
                                WireMessage::FileOffer { file_name, file_size, id, .. } => {
                                    log_event(addr, "📎", "FILE", format!("{} offered '{}' ({} B)", my_username.clone(), file_name, file_size));
                                    let _ = tx_inner.send(WireMessage::FileOffer {
                                        sender: my_username.clone(), file_name, file_size, id
                                    });
                                },
                                WireMessage::FileRequest { file_id, receiver } => {
                                    let _ = tx_inner.send(WireMessage::FileRequest { file_id, receiver });
                                },
                                WireMessage::FileChunk { file_id, chunk_index, total_chunks, data } => {
                                    if data.len() > 64 * 1024 {
                                        continue;
                                    }
                                    let _ = tx_inner.send(WireMessage::FileChunk { file_id, chunk_index, total_chunks, data });
                                },
                                WireMessage::Version { .. } => {},
                                WireMessage::DirectMessage { sender: _, ref target, ref content, ref timestamp, ttl } => {
                                    let safe_msg = WireMessage::DirectMessage {
                                        sender: my_username.clone(),
                                        target: target.clone(),
                                        content: content.clone(),
                                        timestamp: *timestamp,
                                        ttl,
                                    };

                                    let is_online = state_inner.users.iter().any(|u| u.value().username == *target);
                                    if is_online {
                                        let _ = tx_inner.send(safe_msg);
                                    } else {
                                        let target_clone = target.clone();
                                        let expires_at = ttl.map(|secs| Instant::now() + Duration::from_secs(secs));
                                        let stored = StoredMessage { msg: safe_msg, expires_at };
                                        let mut box_entry = state_inner.mailbox.entry(target_clone.clone()).or_insert(Vec::new());
                                        box_entry.push(stored);

                                        log_event(addr, "📥", "SAVED", format!("Message for {} (TTL: {:?})", target_clone, ttl));
                                    }
                                },
                                WireMessage::AdminCommand { command, target } => {
                                    handle_admin_command(
                                        command,
                                        target,
                                        &my_username,
                                        &my_fp,
                                        addr,
                                        &state_inner,
                                        &tx_inner,
                                        log_event,
                                    ).await;
                                },
                                WireMessage::VoicePacket { data: _ } => {
                                    let _ = tx_inner.send(msg);
                                }
                                _ => {}
                            }
                        }
                    }
                } else { break; }
            }
        } => {},

        _ = async {
            loop {
                match rx.recv().await {
                    Ok(msg) => {
                        let should_send = match &msg {
                            WireMessage::Join { group, .. } => group == &my_group,
                            WireMessage::Chat { sender, .. } => {
                                state_inner.users.iter().find(|u| u.value().username == *sender)
                                    .map(|u| u.value().group == my_group)
                                    .unwrap_or(false)
                            },
                            WireMessage::FileOffer { sender, .. } => {
                                sender != &my_username &&
                                state_inner.users.iter().find(|u| u.value().username == *sender)
                                    .map(|u| u.value().group == my_group)
                                    .unwrap_or(false)
                            },
                            WireMessage::FileRequest { receiver, .. } => receiver == &my_username,
                            WireMessage::DirectMessage { target, .. } => target == &my_username,
                            WireMessage::VoicePacket { .. } => true,
                            WireMessage::AdminCommand { .. } => true,
                            WireMessage::Heartbeat => false,
                            WireMessage::PeerList { .. } => true,
                            _ => true,
                        };

                        if should_send {
                            let msg_to_send = if let WireMessage::PeerList { .. } = msg {
                                let fresh_list: Vec<String> = state_inner.users.iter()
                                    .filter(|r| r.value().group == my_group && r.key() != &my_fp)
                                    .map(|r| r.value().username.clone())
                                    .collect();
                                WireMessage::PeerList { peers: fresh_list }
                            } else {
                                msg.clone()
                            };

                            if let Ok(data) = bincode::serialize(&msg_to_send) {
                                if let Ok(pkt) = IsotopePacket::new(&data) {
                                    if let Ok(bytes) = pkt.to_bytes() {
                                        let enc = {
                                            let mut lock = match sess_write.lock() { Ok(l) => l, Err(_) => break };
                                            lock.encrypt(&bytes)
                                        };
                                        if let Ok(data) = enc {
                                            if write_packet_as_server(&mut writer, &data).await.is_err() { break; }
                                        }
                                    }
                                }
                            }
                        }

                        if let WireMessage::AdminCommand { command, target } = &msg {
                            if command == "kick" && target == &my_username {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                break;
                            }
                        }
                    },
                    Err(_) => break,
                }
            }
        } => {}
    }

    state.users.remove(&my_fp);
    log_event(addr, "🔴", "LEFT", format!("{}", my_username.clone().dim()));
    let _ = tx.send(WireMessage::PeerList { peers: vec![] });
    let _ = tx.send(WireMessage::System { content: format!("{} left", my_username) });
    anyhow::bail!("Connection closed normally");
}
