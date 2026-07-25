use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce, AeadCore,
    aead::{Aead, KeyInit}
};
use anyhow::{Result, anyhow, bail, Context};
use rand::{RngCore, rngs::OsRng};

use super::block::{BLOCK_SIZE, NONCE_SIZE, TAG_SIZE, PAYLOAD_SIZE, HEADER_SALT_SIZE};
use super::filesystem::{Vault, Directory};

const HIDDEN_VOLUME_MAGIC: [u8; 32] = [
    0x7a, 0x3f, 0x8c, 0x2d, 0xe1, 0x9b, 0x5f, 0x0a,
    0xc4, 0x72, 0x1e, 0x88, 0x3d, 0xa6, 0x59, 0xf0,
    0x2b, 0x94, 0x6d, 0xe3, 0x17, 0x8a, 0x4c, 0xf5,
    0x0d, 0x61, 0xb8, 0x23, 0x9e, 0x47, 0xca, 0x76,
];

pub struct HiddenVault {
    inner_vault: Vault,
    is_inner_volume: bool,
}

impl HiddenVault {
    pub fn create<P: AsRef<Path>>(
        path: P,
        outer_password: &str,
        inner_password: &str,
        total_size_blocks: u64,
    ) -> Result<Self> {
        let path = path.as_ref();

        if path.exists() {
            bail!("Hidden vault file already exists");
        }

        if total_size_blocks < 4 {
            bail!("Hidden vault needs at least 4 blocks");
        }

        let mut salt = [0u8; HEADER_SALT_SIZE];
        OsRng.fill_bytes(&mut salt);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        file.write_all(&salt)?;

        let mut random_block = vec![0u8; BLOCK_SIZE];
        for _ in 0..total_size_blocks {
            OsRng.fill_bytes(&mut random_block);
            file.write_all(&random_block)?;
        }
        file.sync_all()?;
        drop(file);

        let outer_vault = Vault::open(path, outer_password)?;
        drop(outer_vault);

        let inner_salt = Self::xor_salt(&salt);
        let inner_key = Vault::derive_key(inner_password, &inner_salt)?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let inner_start = HEADER_SALT_SIZE as u64 + (total_size_blocks / 2) * BLOCK_SIZE as u64;
        file.seek(SeekFrom::Start(inner_start))?;

        let inner_dir = Directory::default();
        let dir_data = bincode::serialize(&inner_dir)?;
        let mut padded = dir_data.clone();
        padded.resize(PAYLOAD_SIZE, 0);

        let cipher = XChaCha20Poly1305::new(&inner_key);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, padded.as_ref())
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

        let mut block = Vec::with_capacity(BLOCK_SIZE);
        block.extend_from_slice(&nonce);
        block.extend_from_slice(&ciphertext);
        block.resize(BLOCK_SIZE, 0);

        file.write_all(&block)?;
        file.sync_all()?;

        Self::open(path, inner_password)
    }

    pub fn open<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        let path = path.as_ref();

        if let Ok(vault) = Vault::open(path, password) {
            return Ok(Self {
                inner_vault: vault,
                is_inner_volume: false,
            });
        }

        let mut file = File::open(path)?;
        let mut salt = [0u8; HEADER_SALT_SIZE];
        file.read_exact(&mut salt)?;

        let inner_salt = Self::xor_salt(&salt);
        let inner_key = Vault::derive_key(password, &inner_salt)?;

        let metadata = file.metadata()?;
        let total_bytes = metadata.len() - HEADER_SALT_SIZE as u64;
        let total_blocks = total_bytes / BLOCK_SIZE as u64;
        let inner_start = HEADER_SALT_SIZE as u64 + (total_blocks / 2) * BLOCK_SIZE as u64;

        file.seek(SeekFrom::Start(inner_start))?;

        let mut block = vec![0u8; BLOCK_SIZE];
        file.read_exact(&mut block)?;

        let nonce = XNonce::from_slice(&block[..NONCE_SIZE]);
        let ciphertext = &block[NONCE_SIZE..NONCE_SIZE + PAYLOAD_SIZE + TAG_SIZE];

        let cipher = XChaCha20Poly1305::new(&inner_key);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Invalid password or corrupted vault"))?;

        let directory: Directory = bincode::deserialize(&plaintext)
            .context("Failed to parse inner volume metadata")?;

        drop(file);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        Ok(Self {
            inner_vault: Vault {
                file,
                key: inner_key,
                directory,
                total_blocks: total_blocks / 2,
            },
            is_inner_volume: true,
        })
    }

    fn xor_salt(salt: &[u8; 32]) -> [u8; 32] {
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = salt[i] ^ HIDDEN_VOLUME_MAGIC[i];
        }
        result
    }

    pub fn is_inner(&self) -> bool {
        self.is_inner_volume
    }

    pub fn read_file(&mut self, filename: &str) -> Result<Vec<u8>> {
        self.inner_vault.read_file(filename)
    }

    pub fn write_file(&mut self, filename: &str, data: &[u8]) -> Result<()> {
        self.inner_vault.write_file(filename, data)
    }

    pub fn list_files(&self) -> Vec<String> {
        self.inner_vault.list_files()
    }
}
