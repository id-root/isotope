pub mod defaults;

use serde::{Deserialize, Serialize};
pub use defaults::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network: NetworkConfig,
    pub crypto: CryptoConfig,
    pub ui: UiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub socks_proxy: String,
    pub handshake_timeout_sec: u64,
    pub read_timeout_sec: u64,
    pub jitter_min_ms: u64,
    pub jitter_max_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub wire_packet_size: usize,
    pub pq_tag_size: usize,
    pub plaintext_size: usize,
    pub default_id_file: String,
    pub argon2_memory_kib: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub max_messages: usize,
    pub max_system_logs: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                socks_proxy: DEFAULT_SOCKS_PROXY.to_string(),
                handshake_timeout_sec: HANDSHAKE_TIMEOUT_SEC,
                read_timeout_sec: READ_TIMEOUT_SEC,
                jitter_min_ms: 0,
                jitter_max_ms: 30,
            },
            crypto: CryptoConfig {
                wire_packet_size: WIRE_PACKET_SIZE,
                pq_tag_size: PQ_TAG_SIZE,
                plaintext_size: PLAINTEXT_SIZE,
                default_id_file: DEFAULT_ID_FILE.to_string(),
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            },
            ui: UiConfig {
                max_messages: 10_000,
                max_system_logs: 1_000,
            },
        }
    }
}
