//! # ISOTOPE
//!
//! A metadata-resistant, post-quantum secure messaging system
//! designed for hostile network environments.
//!
//! All traffic is routed through Tor Onion Services and secured with
//! a defense-in-depth hybrid cryptographic stack:
//!
//! - **Layer 1 (Classic):** `Noise_XX_25519_ChaChaPoly_BLAKE2b`
//! - **Layer 2 (Post-Quantum):** `Kyber-1024` Key Encapsulation
//!
//! ## Modules
//!
//! - [`crypto`] — Hybrid Noise+Kyber encryption, identity management, anomaly detection
//! - [`protocol`] — Wire message format, packet serialization, HTTP mimicry
//! - [`network`] — SOCKS5 proxy, multi-hop routing, packet transport
//! - [`client`] — TUI client with chat, vault integration, and file transfer
//! - [`server`] — Hub server with message routing, admin controls, and offline mailbox
//! - [`vault`] — Encrypted block-based virtual filesystem with hidden volumes
//! - [`onion`] — Layered onion routing packet construction

pub mod config;
pub mod error;
pub mod crypto;
pub mod protocol;
pub mod network;
pub mod client;
pub mod server;
pub mod ui;
pub mod onion;
pub mod vault;

// Re-export constants
pub const WIRE_PACKET_SIZE: usize = 4096;
pub const PQ_TAG_SIZE: usize = 16; 
pub const PLAINTEXT_SIZE: usize = 4064; 
pub const HANDSHAKE_TIMEOUT_SEC: u64 = 30;
pub const READ_TIMEOUT_SEC: u64 = 300;
pub const DEFAULT_SOCKS_PROXY: &str = "127.0.0.1:9050";
pub const DEFAULT_ID_FILE: &str = "isotope.id";
