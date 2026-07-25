use argon2::Argon2;
use chacha20poly1305::{Key, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};
use blake3::Hasher;
use anyhow::Result;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZeroizableKeypair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<Key> {
    let mut output_key_material = [0u8; 32];
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output_key_material)
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {}", e))?;
    Ok(*Key::from_slice(&output_key_material))
}

pub fn derive_nonce(password: &str, salt: &[u8], slot_index: u8) -> Nonce {
    let mut nonce_material = [0u8; 12];
    let mut h = Hasher::new();
    h.update(password.as_bytes());
    h.update(b"NONCE_DOMAIN");
    h.update(salt);
    h.update(&[slot_index]);
    nonce_material.copy_from_slice(&h.finalize().as_bytes()[..12]);
    *Nonce::from_slice(&nonce_material)
}
