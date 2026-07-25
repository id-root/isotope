use snow::{TransportState, HandshakeState};
use zeroize::Zeroize;
use anyhow::{Result, bail};
use blake3::Hasher;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use crate::config::defaults::{WIRE_PACKET_SIZE, PQ_TAG_SIZE};

pub struct NoiseSession {
    pub transport: TransportState,
    pub buf: Vec<u8>,
    pub pq_tx_cipher: Option<ChaCha20Poly1305>,
    pub pq_rx_cipher: Option<ChaCha20Poly1305>,
    pub pq_send_nonce: u64,
    pub pq_recv_nonce: u64,
    pub message_count: u64,
    pub session_start: std::time::Instant,
}

const REKEY_MESSAGE_THRESHOLD: u64 = 100;
const REKEY_TIME_THRESHOLD_SECS: u64 = 300;

impl NoiseSession {
    pub fn new(handshake: HandshakeState) -> Result<Self> {
        let transport = handshake.into_transport_mode()?;
        Ok(Self {
            transport,
            buf: vec![0u8; 65535],
            pq_tx_cipher: None,
            pq_rx_cipher: None,
            pq_send_nonce: 0,
            pq_recv_nonce: 0,
            message_count: 0,
            session_start: std::time::Instant::now(),
        })
    }

    pub fn needs_rekey(&self) -> bool {
        self.pq_tx_cipher.is_some() && (
            self.message_count >= REKEY_MESSAGE_THRESHOLD ||
            self.session_start.elapsed().as_secs() >= REKEY_TIME_THRESHOLD_SECS
        )
    }

    pub fn increment_message_count(&mut self) {
        self.message_count += 1;
    }

    pub fn reset_rekey_state(&mut self) {
        self.message_count = 0;
        self.session_start = std::time::Instant::now();
    }

    pub fn upgrade_to_pq(&mut self, shared_secret: &[u8], is_initiator: bool) {
        let mut h_init = Hasher::new();
        h_init.update(b"ISOTOPE_PQ_INITIATOR");
        h_init.update(shared_secret);
        let k_init_bytes = h_init.finalize();
        let k_init = Key::from_slice(k_init_bytes.as_bytes());

        let mut h_resp = Hasher::new();
        h_resp.update(b"ISOTOPE_PQ_RESPONDER");
        h_resp.update(shared_secret);
        let k_resp_bytes = h_resp.finalize();
        let k_resp = Key::from_slice(k_resp_bytes.as_bytes());

        let (tx_key, rx_key) = if is_initiator {
            (k_init, k_resp)
        } else {
            (k_resp, k_init)
        };

        self.pq_tx_cipher = Some(ChaCha20Poly1305::new(tx_key));
        self.pq_rx_cipher = Some(ChaCha20Poly1305::new(rx_key));

        self.pq_send_nonce = 0;
        self.pq_recv_nonce = 0;
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let len = self.transport.read_message(ciphertext, &mut self.buf)?;
        let noise_plain = self.buf[..len].to_vec();

        if let Some(cipher) = &self.pq_rx_cipher {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..].copy_from_slice(&self.pq_recv_nonce.to_be_bytes());
            self.pq_recv_nonce += 1;

            let nonce = Nonce::from_slice(&nonce_bytes);
            let inner_plain = cipher.decrypt(nonce, noise_plain.as_ref())
                .map_err(|_| anyhow::anyhow!("PQ Decryption Failed"))?;

            Ok(inner_plain)
        } else {
            if noise_plain.len() < PQ_TAG_SIZE {
                bail!("Packet too short to contain padding");
            }
            let real_len = noise_plain.len() - PQ_TAG_SIZE;
            Ok(noise_plain[..real_len].to_vec())
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let data_to_send = if let Some(cipher) = &self.pq_tx_cipher {
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..].copy_from_slice(&self.pq_send_nonce.to_be_bytes());
            self.pq_send_nonce += 1;

            let nonce = Nonce::from_slice(&nonce_bytes);
            cipher.encrypt(nonce, plaintext)
                .map_err(|_| anyhow::anyhow!("PQ Encryption Failed"))?
        } else {
            let mut padded = plaintext.to_vec();
            padded.resize(plaintext.len() + PQ_TAG_SIZE, 0);
            padded
        };

        let len = self.transport.write_message(&data_to_send, &mut self.buf)?;

        if len != WIRE_PACKET_SIZE {
            bail!("Encryption failed to produce fixed-size packet");
        }
        Ok(self.buf[..len].to_vec())
    }
}

impl Drop for NoiseSession {
    fn drop(&mut self) {
        self.buf.zeroize();
        self.pq_send_nonce = 0;
        self.pq_recv_nonce = 0;
        self.pq_tx_cipher = None;
        self.pq_rx_cipher = None;
    }
}
