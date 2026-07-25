use anyhow::{Result, Context, bail};
use blake3::Hasher;
use chacha20poly1305::{ChaCha20Poly1305, aead::{Aead, KeyInit}};

use super::keys::ZeroizableKeypair;

pub trait HsmProvider: Send + Sync {
    fn get_public_key(&self) -> Result<Vec<u8>>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn is_available(&self) -> bool;
}

pub struct SoftwareHsm {
    keypair: Option<ZeroizableKeypair>,
}

impl SoftwareHsm {
    pub fn new() -> Self {
        Self { keypair: None }
    }

    pub fn load_keypair(&mut self, keypair: ZeroizableKeypair) {
        self.keypair = Some(keypair);
    }
}

impl Default for SoftwareHsm {
    fn default() -> Self {
        Self::new()
    }
}

impl HsmProvider for SoftwareHsm {
    fn get_public_key(&self) -> Result<Vec<u8>> {
        self.keypair
            .as_ref()
            .map(|k| k.public.clone())
            .context("No keypair loaded")
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let kp = self.keypair.as_ref().context("No keypair loaded for signing")?;
        let key: [u8; 32] = kp.private[..32]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Private key too short for BLAKE3 keyed hash"))?;
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(data);
        Ok(hasher.finalize().as_bytes().to_vec())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let kp = self.keypair.as_ref().context("No keypair loaded for decryption")?;
        let key_material = {
            let mut hasher = Hasher::new();
            hasher.update(b"ISOTOPE_HSM_DECRYPT");
            hasher.update(&kp.private);
            hasher.finalize()
        };
        let key = chacha20poly1305::Key::from_slice(key_material.as_bytes());
        let cipher = ChaCha20Poly1305::new(key);

        if ciphertext.len() < 12 {
            bail!("Ciphertext too short — missing nonce");
        }
        let nonce = chacha20poly1305::Nonce::from_slice(&ciphertext[..12]);
        let ct = &ciphertext[12..];
        cipher
            .decrypt(nonce, ct)
            .map_err(|_| anyhow::anyhow!("HSM decryption failed — invalid ciphertext or key"))
    }

    fn is_available(&self) -> bool {
        self.keypair.is_some()
    }
}
