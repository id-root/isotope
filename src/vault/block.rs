use anyhow::{Result, anyhow, bail};
use chacha20poly1305::{
    XChaCha20Poly1305, Key, XNonce, AeadCore,
    aead::{Aead, KeyInit}
};
use rand::rngs::OsRng;

pub const BLOCK_SIZE: usize = 4096;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const PAYLOAD_SIZE: usize = BLOCK_SIZE - NONCE_SIZE - TAG_SIZE; // 4056
pub const HEADER_SALT_SIZE: usize = 32;

pub fn prepare_block(key: &Key, data: &[u8]) -> Result<Vec<u8>> {
    let mut padded = data.to_vec();
    if padded.len() > PAYLOAD_SIZE {
        bail!("Data exceeds block capacity");
    }
    padded.resize(PAYLOAD_SIZE, 0);

    let cipher = XChaCha20Poly1305::new(key);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, padded.as_ref())
        .map_err(|_| anyhow!("Encryption failed"))?;

    let mut block = Vec::with_capacity(BLOCK_SIZE);
    block.extend_from_slice(nonce.as_slice());
    block.extend_from_slice(&ciphertext);

    Ok(block)
}

pub fn open_block(key: &Key, block: &[u8]) -> Result<Vec<u8>> {
    if block.len() != BLOCK_SIZE {
        bail!("Block size mismatch");
    }
    let nonce = XNonce::from_slice(&block[..NONCE_SIZE]);
    let ciphertext = &block[NONCE_SIZE..];

    let cipher = XChaCha20Poly1305::new(key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed (Integrity Check)"))?;

    Ok(plaintext)
}
