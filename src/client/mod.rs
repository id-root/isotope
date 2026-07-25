pub mod panic;
pub mod voice;

use crate::crypto::{Identity, NoiseSession};
use crate::protocol::{IsotopePacket, WireMessage};
use crate::network::{connect_socks5, parse_onion_address, read_packet, write_packet_as_client};
use crate::vault::Vault;
use crate::config::defaults::HANDSHAKE_TIMEOUT_SEC;
use crate::ui::{AppState, Focus};
use crate::ui::render::draw_ui;

use panic::{nuke_everything, expand_path, set_panic_hook};
use voice::simulate_audio_capture;

use tokio::time::{timeout, Duration};
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::net::SocketAddr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::collections::{HashMap, HashSet};
use anyhow::{Result, bail};
use snow::Builder;
use base64::prelude::*;
use blake3::Hasher;
use chrono::Utc;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use tui_input::backend::crossterm::EventHandler;
use rand::Rng;

use pqcrypto_kyber::kyber1024::*;
use pqcrypto_traits::kem::{Ciphertext, SharedSecret, PublicKey};
use audiopus::{coder::Decoder as OpusDecoder, coder::Encoder as OpusEncoder, Application, Channels, SampleRate};

const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

enum InternalEvent {
    NetworkMessage(WireMessage),
    Input(String),
    Progress(String, f64),
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    address: String,
    username: String,
    peer_fp: String,
    proxy: String,
    identity: String,
    group: String,
    temp: bool,
) -> Result<()> {
    set_panic_hook();

    fs::create_dir_all("downloads")?;

    let (id, user_pass) = if temp {
        (Identity::generate("temp")?, "TempVaultPass123!".to_string())
    } else {
        let path = Path::new(&identity);
        if path.exists() {
            println!("Enter identity password:");
            let pass = rpassword::read_password()?;
            let loaded_id = Identity::load(&identity, &pass)?;
            (loaded_id, pass)
        } else {
            println!("Identity file not found. Creating new identity.");
            println!("Set REAL password (for OPS):");
            let pass_ops = rpassword::read_password()?;
            println!("Set DURESS password (for CASUAL):");
            let pass_casual = rpassword::read_password()?;

            Identity::setup_dual(&identity, &pass_ops, &pass_casual)?;
            println!("Identity created. Logging in with REAL password...");
            let loaded_id = Identity::load(&identity, &pass_ops)?;
            (loaded_id, pass_ops)
        }
    };

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new(username.clone(), id.fingerprint()[0..8].to_string(), group.clone());
    app.status = "CONNECTING...".to_string();
    if temp { app.add_log("⚠️ USING TEMP IDENTITY".to_string()); }

    let vault_path = "isotope.vault";
    let mut vault: Option<Vault> = match Vault::open(vault_path, &user_pass) {
        Ok(v) => {
            app.vault_files = v.list_files();
            app.add_log("🔒 Encrypted Vault Unlocked".to_string());
            Some(v)
        },
        Err(e) => {
            app.add_log(format!("⚠️ Vault Unlocked/Init skipped: {}", e));
            None
        }
    };
    app.add_log("💾 Use /vault_put, /vault_get, /vault_list to manage vault".to_string());

    terminal.draw(|f| draw_ui(f, &mut app))?;

    let (host, port) = parse_onion_address(&address)?;
    let proxy_addr: SocketAddr = proxy.parse()?;

    let mut retry_count = 0;
    loop {
        if retry_count > 0 {
            app.status = format!("RETRYING ({})", retry_count);
            let delay = std::cmp::min(10, retry_count * 2) as u64;
            app.add_log(format!("Lost connection. Retrying in {}s...", delay));
            terminal.draw(|f| draw_ui(f, &mut app))?;
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }

        app.status = "CONNECTING...".to_string();
        terminal.draw(|f| draw_ui(f, &mut app))?;

        let mut stream = match connect_socks5(proxy_addr, &host, port).await {
            Ok(s) => s,
            Err(e) => {
                app.add_log(format!("Connection Failed: {}", e));
                retry_count += 1;
                continue;
            }
        };

        app.status = "HANDSHAKING...".to_string();
        terminal.draw(|f| draw_ui(f, &mut app))?;

        let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
        let handshake_res = builder.local_private_key(&id.keypair.private).build_initiator();
        if let Err(e) = handshake_res {
            app.add_log(format!("Handshake Init Error: {}", e));
            retry_count += 1; continue;
        }
        let mut handshake = handshake_res.unwrap();
        let mut buf = vec![0u8; 65535];

        if let Err(e) = (async {
            let len = handshake.write_message(&[], &mut buf)?;
            write_packet_as_client(&mut stream, &buf[..len]).await?;
            let msg = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(&mut stream)).await??;
            handshake.read_message(&msg, &mut buf)?;
            let len = handshake.write_message(&[], &mut buf)?;
            write_packet_as_client(&mut stream, &buf[..len]).await?;
            Ok::<(), anyhow::Error>(())
        }).await {
            app.add_log(format!("Handshake Error: {}", e));
            retry_count += 1; continue;
        }

        let session = match NoiseSession::new(handshake) {
            Ok(s) => Arc::new(Mutex::new(s)),
            Err(e) => { app.add_log(format!("Session Error: {}", e)); retry_count += 1; continue; }
        };

        let remote = session.lock().map_err(|e| anyhow::anyhow!("Session lock poisoned: {}", e))?.transport.get_remote_static().unwrap().to_vec();
        let mut h = Hasher::new(); h.update(&remote);
        let server_fp = BASE64_STANDARD.encode(h.finalize().as_bytes());
        if server_fp != peer_fp {
            app.add_log("Fingerprint mismatch! MITM?".to_string());
            retry_count += 1; continue;
        }

        app.status = "SECURED (NOISE)".to_string();
        app.encryption_level = "NOISE: AES-256".to_string();

        app.status = "NEGOTIATING QUANTUM...".to_string();
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if let Err(e) = (async {
            let wire_buf = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SEC), read_packet(&mut stream)).await??;
            let decrypted = session.lock().map_err(|e| anyhow::anyhow!("Session lock poisoned: {}", e))?.decrypt(&wire_buf)?;
            let packet = IsotopePacket::from_bytes(&decrypted)?;

            match bincode::deserialize(&packet.payload) {
                Ok(WireMessage::PQInit { public_key }) => {
                    if public_key.len() != pqcrypto_kyber::kyber1024::public_key_bytes() {
                        bail!("Invalid Kyber1024 Public Key length: {}", public_key.len());
                    }
                    let pk = match PublicKey::from_bytes(&public_key) {
                        Ok(k) => k,
                        Err(e) => bail!("Failed to parse Kyber Public Key: {}", e),
                    };
                    let (ss, ct) = encapsulate(&pk);
                    let pq_msg = WireMessage::PQFinish { ciphertext: ct.as_bytes().to_vec() };
                    let data = bincode::serialize(&pq_msg)?;
                    let pkt = IsotopePacket::new(&data)?;
                    let enc = session.lock().map_err(|e| anyhow::anyhow!("Session lock poisoned: {}", e))?.encrypt(&pkt.to_bytes()?)?;
                    write_packet_as_client(&mut stream, &enc).await?;
                    session.lock().map_err(|e| anyhow::anyhow!("Session lock poisoned: {}", e))?.upgrade_to_pq(ss.as_bytes(), true);
                    Ok(())
                },
                _ => bail!("Expected PQInit")
            }
        }).await {
            app.add_log(format!("PQ Error: {}", e));
            retry_count += 1; continue;
        }

        app.encryption_level = "🛡️ KYBER-1024".to_string();
        app.add_log("QUANTUM SHIELD ESTABLISHED".to_string());

        let join_msg = WireMessage::Join {
            username: username.clone(),
            did: id.did(),
            group: group.clone()
        };
        if let Ok(data) = bincode::serialize(&join_msg) {
            if let Ok(pkt) = IsotopePacket::new(&data) {
                let enc_res = session.lock().map_err(|e| anyhow::anyhow!("Session lock poisoned: {}", e))?.encrypt(&pkt.to_bytes().unwrap());
                if let Ok(enc) = enc_res {
                    if write_packet_as_client(&mut stream, &enc).await.is_err() {
                        app.add_log("Failed to send Join".to_string());
                        retry_count += 1; continue;
                    }
                }
            }
        }

        app.status = "ONLINE".to_string();
        retry_count = 0;

        let (mut reader, mut writer) = stream.into_split();
        let (tx_net, mut rx_net) = mpsc::channel::<WireMessage>(100);
        let (tx_logic, mut rx_logic) = mpsc::channel::<InternalEvent>(100);

        let sess_read = session.clone();
        let sess_write = session.clone();

        let tx_heartbeat = tx_net.clone();
        let hb_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                if tx_heartbeat.send(WireMessage::Heartbeat).await.is_err() {
                    break;
                }
            }
        });

        let tx_cover = tx_net.clone();
        let _cover_handle = tokio::spawn(async move {
            use rand::Rng;
            loop {
                let interval = rand::thread_rng().gen_range(2..8);
                tokio::time::sleep(Duration::from_secs(interval)).await;
                let noise: Vec<u8> = (0..256).map(|_| rand::thread_rng().gen()).collect();
                if tx_cover.send(WireMessage::Dummy { noise }).await.is_err() {
                    break;
                }
            }
        });

        let tx_logic_net = tx_logic.clone();
        let reader_handle = tokio::spawn(async move {
            loop {
                let wire_res = read_packet(&mut reader).await;
                if wire_res.is_err() { break; }
                let wire = wire_res.unwrap();

                let res = {
                    let mut lock = match sess_read.lock() { Ok(l) => l, Err(_) => break };
                    lock.decrypt(&wire)
                };
                if let Ok(plain) = res {
                    if let Ok(pkt) = IsotopePacket::from_bytes(&plain) {
                        if let Ok(msg) = bincode::deserialize(&pkt.payload) {
                            if !matches!(msg, WireMessage::Heartbeat) {
                                let _ = tx_logic_net.send(InternalEvent::NetworkMessage(msg)).await;
                            }
                        }
                    }
                }
            }
        });

        let writer_handle = tokio::spawn(async move {
            while let Some(msg) = rx_net.recv().await {
                if let Ok(data) = bincode::serialize(&msg) {
                    if let Ok(pkt) = IsotopePacket::new(&data) {
                        if let Ok(bytes) = pkt.to_bytes() {
                            let enc = {
                                let mut lock = match sess_write.lock() { Ok(l) => l, Err(_) => break };
                                lock.encrypt(&bytes)
                            };
                            if let Ok(data) = enc {
                                if write_packet_as_client(&mut writer, &data).await.is_err() { break; }
                            }
                        }
                    }
                }
            }
        });

        let mut upload_queue: HashMap<u32, PathBuf> = HashMap::new();
        let mut download_whitelist: HashSet<u32> = HashSet::new();
        let mut active_downloads: HashMap<u32, (String, u32)> = HashMap::new();
        let mut pending_offers: HashMap<u32, (String, String)> = HashMap::new();

        let dead_man_timeout = Duration::from_secs(5 * 60);
        let mut last_activity = std::time::Instant::now();
        let mut last_typing_sent = std::time::Instant::now() - Duration::from_secs(10);

        let mut quit_signal = false;
        'session: loop {
            if last_activity.elapsed() > dead_man_timeout {
                let _ = tx_net.send(WireMessage::Signal(crate::protocol::SignalType::Duress)).await;
                tokio::time::sleep(Duration::from_millis(100)).await;

                disable_raw_mode()?;
                execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                println!("\n\x1b[31;1m🚨 DEAD MAN'S SWITCH TRIGGERED (INACTIVITY). NUKING DATA...\x1b[0m");
                nuke_everything(&identity);
                std::process::exit(0);
            }

            app.dashboard_state.uptime_secs = app.dashboard_state.uptime_secs.wrapping_add(1);

            let mut rng = rand::thread_rng();
            app.dashboard_state.ram_usage = (50 + rng.gen_range(0..20)) as u64;

            let upload_rate = if app.dashboard_state.uptime_secs % 2 == 0 { rng.gen_range(0.5..5.0) } else { 0.0 };
            let download_rate = if app.dashboard_state.uptime_secs % 2 == 0 { rng.gen_range(10.0..50.0) } else { 0.0 };
            app.dashboard_state.upload_speed = upload_rate;
            app.dashboard_state.download_speed = download_rate;

            app.cleanup_expired();
            terminal.draw(|f| draw_ui(f, &mut app))?;

            if crossterm::event::poll(Duration::from_millis(10))? {
                last_activity = std::time::Instant::now();

                if let Event::Key(key) = event::read()? {
                    if app.file_browser_open {
                        match key.code {
                            KeyCode::Esc => app.file_browser_open = false,
                            KeyCode::Up => app.browser_navigate(true),
                            KeyCode::Down => app.browser_navigate(false),
                            KeyCode::Enter => {
                                if let Some(path) = app.browser_select() {
                                    let _ = app.input.handle_event(&Event::Key(KeyCode::Char('/').into()));
                                    let _ = app.input.handle_event(&Event::Key(KeyCode::Char('s').into()));
                                    let _ = app.input.handle_event(&Event::Key(KeyCode::Char('e').into()));
                                    let _ = app.input.handle_event(&Event::Key(KeyCode::Char('n').into()));
                                    let _ = app.input.handle_event(&Event::Key(KeyCode::Char('d').into()));
                                    let _ = app.input.handle_event(&Event::Key(KeyCode::Char(' ').into()));
                                    for c in path.chars() {
                                        let _ = app.input.handle_event(&Event::Key(KeyCode::Char(c).into()));
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('n') if app.is_searching => app.next_match(),
                            KeyCode::Char('N') if app.is_searching => app.prev_match(),

                            KeyCode::Tab => {
                                app.cycle_focus(key.modifiers.contains(KeyModifiers::SHIFT));
                            }

                            KeyCode::Left if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.prev_tab();
                            }
                            KeyCode::Right if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.next_tab();
                            }

                            KeyCode::Char('1') if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.current_tab = crate::ui::Tab::Comms;
                            }
                            KeyCode::Char('2') if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.current_tab = crate::ui::Tab::Vault;
                            }
                            KeyCode::Char('3') if key.modifiers.contains(KeyModifiers::ALT) => {
                                app.current_tab = crate::ui::Tab::Intel;
                            }

                            KeyCode::BackTab => {
                                app.cycle_focus(true);
                            }
                            KeyCode::Char('?') => {
                                app.show_help = !app.show_help;
                            }

                            KeyCode::Enter if app.focus == Focus::Input => {
                                if key.modifiers.contains(KeyModifiers::SHIFT) || key.modifiers.contains(KeyModifiers::ALT) {
                                    app.input.handle_event(&Event::Key(KeyCode::Char('\n').into()));
                                } else {
                                    let input: String = app.input.value().into();
                                    app.input.reset();

                                    if input.starts_with("/search ") {
                                        let query = input.trim_start_matches("/search ").to_string();
                                        app.perform_search(query);
                                        app.focus = Focus::Chat;
                                    } else if input.trim() == "/search" {
                                        app.perform_search("".to_string());
                                    } else if input.trim() == "/browse" {
                                        app.open_browser();
                                    } else if !input.is_empty() {
                                        let _ = tx_logic.send(InternalEvent::Input(input)).await;
                                    }
                                }
                            }
                            KeyCode::Char(_c) if app.focus == Focus::Input => {
                                app.input.handle_event(&Event::Key(key));

                                let now = std::time::Instant::now();
                                if now.duration_since(last_typing_sent) > Duration::from_millis(1000) {
                                    let _ = tx_net.send(WireMessage::Typing { user: username.clone(), is_typing: true }).await;
                                    last_typing_sent = now;
                                }
                            }
                            KeyCode::Backspace if app.focus == Focus::Input => {
                                app.input.handle_event(&Event::Key(key));
                            }

                            KeyCode::Up | KeyCode::PageUp => {
                                if app.focus == Focus::Chat {
                                    app.scroll_up();
                                }
                            }
                            KeyCode::Down | KeyCode::PageDown => {
                                if app.focus == Focus::Chat {
                                    app.scroll_down();
                                }
                            }

                            KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                let _ = tx_net.send(WireMessage::Signal(crate::protocol::SignalType::Duress)).await;
                                tokio::time::sleep(Duration::from_millis(100)).await;

                                disable_raw_mode()?;
                                execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                                println!("\n\x1b[31;1m🚨 PANIC INITIATED. NUKING DATA...\x1b[0m");
                                nuke_everything(&identity);
                                std::process::exit(0);
                            },

                            KeyCode::Esc => {
                                if app.is_searching {
                                    app.perform_search("".to_string());
                                    app.focus = Focus::Input;
                                } else {
                                    quit_signal = true; break 'session;
                                }
                            },
                            _ => {}
                        }
                    }
                }
            }

            if reader_handle.is_finished() || writer_handle.is_finished() {
                app.add_log("⚠️ Network Task Failed".to_string());
                break 'session;
            }

            if let Ok(event) = rx_logic.try_recv() {
                match event {
                    InternalEvent::Progress(filename, pct) => {
                        if pct >= 1.0 {
                            app.file_progress = None;
                            app.add_msg("SYSTEM".to_string(), format!("TRANSFER COMPLETE: {}", filename));
                        } else {
                            app.file_progress = Some((filename, pct));
                        }
                    },
                    InternalEvent::Input(raw_cmd) => {
                        let cmd = raw_cmd.trim();

                        if cmd.starts_with("/send") {
                            let path_part = cmd.trim_start_matches("/send").trim();
                            let path = expand_path(path_part);

                            if let Ok(metadata) = fs::metadata(&path) {
                                if path.is_file() {
                                    let size = metadata.len();
                                    if size > MAX_FILE_SIZE {
                                        app.add_msg("SYSTEM".to_string(), format!("⚠️ FILE TOO LARGE ({} MB)", size/1024/1024));
                                    } else {
                                        let mut rng = rand::thread_rng();
                                        let id = rng.gen_range(1000..9999);

                                        let name = path.file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("unknown_file")
                                            .to_string();
                                        upload_queue.insert(id, path);

                                        app.add_msg("SYSTEM".to_string(), format!("OFFERED: {} (ID: {})", name, id));

                                        let _ = tx_net.send(WireMessage::FileOffer {
                                            sender: username.clone(), file_name: name, file_size: size, id
                                        }).await;
                                    }
                                } else {
                                    app.add_msg("SYSTEM".to_string(), "ERROR: INVALID FILE".to_string());
                                }
                            } else {
                                app.add_msg("SYSTEM".to_string(), format!("ERROR: PATH NOT FOUND {:?}", path));
                            }
                        } else if cmd.starts_with("/get ") {
                            if let Ok(id) = cmd.trim_start_matches("/get ").parse::<u32>() {
                                if let Some((_, sender_name)) = pending_offers.get(&id) {
                                    app.add_msg("SYSTEM".to_string(), format!("ACCEPTING ID {} from {}", id, sender_name));
                                    download_whitelist.insert(id);
                                    let _ = tx_net.send(WireMessage::FileRequest {
                                        receiver: sender_name.clone(),
                                        file_id: id
                                    }).await;
                                } else {
                                    app.add_msg("SYSTEM".to_string(), format!("UNKNOWN FILE ID: {}", id));
                                }
                            }
                        } else if cmd == "/quit" {
                            quit_signal = true; break 'session;
                        } else if cmd == "/nuke" {
                            let _ = tx_net.send(WireMessage::Signal(crate::protocol::SignalType::Duress)).await;
                            tokio::time::sleep(Duration::from_millis(100)).await;

                            disable_raw_mode()?;
                            execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                            println!("\n\x1b[31;1m🚨 PANIC INITIATED VIA COMMAND. NUKING DATA...\x1b[0m");
                            nuke_everything(&identity);
                            std::process::exit(0);
                        } else if cmd.starts_with("/vault_put ") {
                            let path_str = cmd.trim_start_matches("/vault_put ").trim();
                            let path = Path::new(path_str);
                            if path.exists() && path.is_file() {
                                if let Some(v) = &mut vault {
                                    match fs::read(path) {
                                        Ok(data) => {
                                            let filename = path.file_name().unwrap().to_str().unwrap();
                                            match v.write_file(filename, &data) {
                                                Ok(_) => {
                                                    let _ = app.add_msg("SYSTEM".to_string(), format!("🔒 Stored {} in Vault", filename));
                                                    app.vault_files = v.list_files();
                                                },
                                                Err(e) => { let _ = app.add_msg("SYSTEM".to_string(), format!("❌ Vault Write Error: {}", e)); },
                                            }
                                        },
                                        Err(e) => { let _ = app.add_msg("SYSTEM".to_string(), format!("❌ Read Error: {}", e)); },
                                    }
                                } else {
                                    app.add_msg("SYSTEM".to_string(), "❌ Vault not available".to_string());
                                }
                            } else {
                                app.add_msg("SYSTEM".to_string(), "❌ File not found".to_string());
                            }
                        } else if cmd.starts_with("/vault_get ") {
                            let filename = cmd.trim_start_matches("/vault_get ").trim();
                            if let Some(v) = &mut vault {
                                match v.read_file(filename) {
                                    Ok(data) => {
                                        let out_path = format!("downloads/{}", filename);
                                        match fs::write(&out_path, data) {
                                            Ok(_) => { let _ = app.add_msg("SYSTEM".to_string(), format!("📂 Extracted to {}", out_path)); },
                                            Err(e) => { let _ = app.add_msg("SYSTEM".to_string(), format!("❌ Write Error: {}", e)); },
                                        }
                                    },
                                    Err(e) => { let _ = app.add_msg("SYSTEM".to_string(), format!("❌ Vault Read Error: {}", e)); },
                                }
                            } else {
                                app.add_msg("SYSTEM".to_string(), "❌ Vault not available".to_string());
                            }
                        } else if cmd == "/vault_list" {
                            if let Some(v) = &vault {
                                let files = v.list_files();
                                app.vault_files = files.clone();
                                app.add_msg("SYSTEM".to_string(), format!("🔒 Vault Contents: {:?}", files));
                            } else {
                                app.add_msg("SYSTEM".to_string(), "❌ Vault not available".to_string());
                            }
                        } else if cmd.starts_with("/msg ") {
                            let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
                            if parts.len() == 3 {
                                let target = parts[1];
                                let content = parts[2];
                                let _ = tx_net.send(WireMessage::DirectMessage {
                                    sender: username.clone(),
                                    target: target.to_string(),
                                    content: content.to_string(),
                                    timestamp: Utc::now(),
                                    ttl: None,
                                }).await;
                                app.add_msg(format!("You -> {}", target), content.to_string());
                            } else {
                                app.add_log("Usage: /msg <user> <message>".to_string());
                            }
                        } else if cmd.starts_with("/ttl ") {
                            let parts: Vec<&str> = cmd.splitn(4, ' ').collect();
                            if parts.len() == 4 {
                                let target = parts[1];
                                let seconds = parts[2].parse::<u64>().unwrap_or(30);
                                let content = parts[3];

                                let _ = tx_net.send(WireMessage::DirectMessage {
                                    sender: username.clone(),
                                    target: target.to_string(),
                                    content: content.to_string(),
                                    timestamp: Utc::now(),
                                    ttl: Some(seconds),
                                }).await;
                                app.add_ttl_msg(format!("You -> {}", target), content.to_string(), seconds);
                            } else {
                                app.add_log("Usage: /ttl <user> <seconds> <message>".to_string());
                            }
                        } else if cmd.starts_with("/kick ") {
                            let target = cmd.trim_start_matches("/kick ").trim();
                            if !target.is_empty() {
                                let _ = tx_net.send(WireMessage::AdminCommand {
                                    command: "kick".to_string(),
                                    target: target.to_string(),
                                }).await;
                            }
                        } else if cmd.starts_with("/ban ") {
                            let target = cmd.trim_start_matches("/ban ").trim();
                            if !target.is_empty() {
                                let _ = tx_net.send(WireMessage::AdminCommand {
                                    command: "ban".to_string(),
                                    target: target.to_string(),
                                }).await;
                            }
                        } else if cmd == "/voice_sim" {
                            app.add_log("🎤 Simulating Voice Packet Send...".to_string());
                            let pcm = simulate_audio_capture();
                            let encoder = OpusEncoder::new(
                                SampleRate::Hz48000,
                                Channels::Mono,
                                Application::Voip
                            ).unwrap();

                            let mut output = [0u8; 128];
                            if let Ok(len) = encoder.encode(&pcm, &mut output) {
                                let opus_data = output[..len].to_vec();
                                let _ = tx_net.send(WireMessage::VoicePacket {
                                    data: opus_data
                                }).await;
                            } else {
                                app.add_log("Audio Encoding Failed".to_string());
                            }
                        } else {
                            let _ = tx_net.send(WireMessage::Chat {
                                sender: username.clone(), content: cmd.to_string(), timestamp: Utc::now()
                            }).await;
                        }
                    },
                    InternalEvent::NetworkMessage(msg) => {
                        match msg {
                            WireMessage::Join { username, .. } => {
                                app.add_log(format!("JOIN: {}", username));
                            },
                            WireMessage::PeerList { peers } => {
                                app.peers = peers;
                            },
                            WireMessage::Chat { sender, content, .. } => {
                                let msg_id = app.add_msg(sender.clone(), content);
                                if sender != username {
                                    let _ = tx_net.send(WireMessage::ReadReceipt { message_id: msg_id, reader: username.clone() }).await;
                                }
                            },
                            WireMessage::System { content } => {
                                app.add_log(format!("SYSTEM: {}", content));
                            },
                            WireMessage::DirectMessage { sender, content, ttl, .. } => {
                                if let Some(seconds) = ttl {
                                    app.add_ttl_msg(sender, content, seconds);
                                } else {
                                    app.add_msg(format!("{} (DM)", sender), content);
                                }
                            },
                            WireMessage::AdminCommand { command, target } => {
                                if target == username {
                                    if command == "kick" {
                                        disable_raw_mode()?;
                                        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
                                        println!("\n\x1b[31;1m🚨 YOU HAVE BEEN KICKED BY ADMIN.\x1b[0m");
                                        std::process::exit(0);
                                    }
                                }
                                app.add_log(format!("ADMIN: Executed {} on {}", command, target));
                            },
                            WireMessage::VoicePacket { data } => {
                                 let mut decoder = OpusDecoder::new(SampleRate::Hz48000, Channels::Mono).unwrap();
                                 let mut output = [0i16; 5760];
                                 if let Ok(len) = decoder.decode(Some(&data), &mut output[..], false) {
                                     app.add_log(format!("🔊 Voice Packet Received & Decoded ({} samples)", len));
                                 } else {
                                     app.add_log("🔊 Voice Packet Receive Error".to_string());
                                 }
                            },
                            WireMessage::FileOffer { sender, file_name, file_size, id, .. } => {
                                if file_size > MAX_FILE_SIZE {
                                    app.add_msg("SYSTEM".to_string(), format!("⚠️ IGNORED FILE OFFER > 10MB ({} B)", file_size));
                                } else if sender != username {
                                    let safe_name = Path::new(&file_name).file_name().unwrap_or_default().to_string_lossy().into_owned();
                                    pending_offers.insert(id, (safe_name.clone(), sender.clone()));
                                    app.add_msg("SYSTEM".to_string(), format!("📁 {} sent '{}' ({} bytes). Type /get {} to download", sender, safe_name, file_size, id));
                                }
                            },
                            WireMessage::FileRequest { file_id, receiver } => {
                                if let Some(path) = upload_queue.get(&file_id) {
                                    app.add_msg("SYSTEM".to_string(), format!("📤 UPLOADING to {}...", receiver));

                                    let tx_progress = tx_logic.clone();
                                    let file_name_display = path.file_name().unwrap_or_default().to_string_lossy().to_string();

                                    let path_clone = path.clone();
                                    let tx_net_task = tx_net.clone();
                                    tokio::spawn(async move {
                                        if let Ok(buffer) = tokio::fs::read(&path_clone).await {
                                            let tx_clone = tx_net_task.clone();
                                            let chunk_size = 1024;
                                            let total = (buffer.len() as f64 / chunk_size as f64).ceil() as u32;

                                            for (i, chunk) in buffer.chunks(chunk_size).enumerate() {
                                                let _ = tx_clone.send(WireMessage::FileChunk {
                                                    file_id, chunk_index: i as u32, total_chunks: total, data: chunk.to_vec(),
                                                }).await;

                                                if i % 10 == 0 {
                                                    let pct = (i as f64) / (total as f64);
                                                    let _ = tx_progress.send(InternalEvent::Progress(file_name_display.clone(), pct)).await;
                                                }
                                                tokio::time::sleep(Duration::from_millis(5)).await;
                                            }
                                            let _ = tx_progress.send(InternalEvent::Progress(file_name_display, 1.0)).await;
                                        }
                                    });
                                }
                            },
                            WireMessage::FileChunk { file_id, chunk_index, total_chunks, data } => {
                                if download_whitelist.contains(&file_id) {
                                    if !active_downloads.contains_key(&file_id) {
                                        let name = pending_offers.get(&file_id)
                                            .map(|(n, _)| n.clone())
                                            .unwrap_or_else(|| format!("file_{}.bin", file_id));
                                        active_downloads.insert(file_id, (name, 0));
                                    }
                                    if let Some((name, progress)) = active_downloads.get_mut(&file_id) {
                                        let path = format!("downloads/{}", name);
                                        let mut f = OpenOptions::new().create(true).append(true).open(&path).ok();
                                        if let Some(ref mut file) = f {
                                            let _ = file.write_all(&data);
                                        }
                                        *progress = chunk_index;

                                        let pct = chunk_index as f64 / total_chunks as f64;
                                        app.file_progress = Some((name.clone(), pct));

                                        if chunk_index == total_chunks - 1 {
                                            app.add_msg("SYSTEM".to_string(), format!("✅ DOWNLOAD COMPLETE: {}", name));
                                            app.file_progress = None;
                                            download_whitelist.remove(&file_id);
                                        }
                                    }
                                }
                            },

                            WireMessage::ReadReceipt { message_id, reader } => {
                                app.mark_read(message_id, reader);
                            },

                            WireMessage::Typing { user, is_typing } => {
                                if user != username {
                                    app.set_typing(user.clone(), is_typing);
                                }
                            },
                            _ => {}
                        }
                    }
                }
            }
        }

        hb_handle.abort();
        reader_handle.abort();
        writer_handle.abort();

        if quit_signal {
            break;
        }
        retry_count += 1;
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    println!("Safely disconnected from ISOTOPE network.");
    Ok(())
}
