use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::collections::HashMap;
use chacha20poly1305::Key;
use anyhow::{Result, anyhow, bail, Context};
use serde::{Serialize, Deserialize};
use rand::{RngCore, rngs::OsRng};

use super::block::{BLOCK_SIZE, PAYLOAD_SIZE, HEADER_SALT_SIZE, prepare_block, open_block};

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Directory {
    pub files: HashMap<String, FileEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub size: u64,
    pub blocks: Vec<u64>,
}

pub struct Vault {
    pub file: File,
    pub key: Key,
    pub directory: Directory,
    pub total_blocks: u64,
}

impl Vault {
    pub fn open<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        let path = path.as_ref();
        let exists = path.exists();

        if !exists {
            if password.len() < 8 {
                bail!("Password must be at least 8 characters");
            }
            if !password.chars().any(|c| c.is_uppercase()) {
                bail!("Password must contain an uppercase letter");
            }
            if !password.chars().any(|c| c.is_numeric()) {
                bail!("Password must contain a number");
            }
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        if !exists {
            let mut salt = [0u8; HEADER_SALT_SIZE];
            OsRng.fill_bytes(&mut salt);
            file.write_all(&salt)?;

            let key = Self::derive_key(password, &salt)?;

            let dir = Directory::default();
            let mut vault = Self {
                file,
                key,
                directory: dir,
                total_blocks: 1,
            };

            vault.write_metadata()?;
            return Ok(vault);
        }

        let mut salt = [0u8; HEADER_SALT_SIZE];
        if file.read_exact(&mut salt).is_err() {
            bail!("Vault file too short");
        }

        let key = Self::derive_key(password, &salt)?;
        let mut vault = Self {
            file,
            key,
            directory: Directory::default(),
            total_blocks: 0,
        };

        vault.read_metadata()?;

        let metadata = vault.file.metadata()?;
        let len = metadata.len();
        if len < HEADER_SALT_SIZE as u64 {
            bail!("Corrupted vault");
        }
        vault.total_blocks = (len - HEADER_SALT_SIZE as u64) / BLOCK_SIZE as u64;

        Ok(vault)
    }

    pub fn derive_key(password: &str, salt: &[u8]) -> Result<Key> {
        let mut output_key_material = [0u8; 32];
        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| anyhow::anyhow!("Argon2 params error: {}", e))?;
        let argon2 = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut output_key_material)
            .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
        Ok(*Key::from_slice(&output_key_material))
    }

    fn read_metadata(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(HEADER_SALT_SIZE as u64))?;
        let mut block = vec![0u8; BLOCK_SIZE];
        if self.file.read_exact(&mut block).is_err() {
            bail!("Could not read metadata block");
        }

        let plaintext = open_block(&self.key, &block)?;

        let len_bytes: [u8; 4] = plaintext[..4].try_into()?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        if len > plaintext.len() - 4 {
            bail!("Corrupt metadata length");
        }

        let dir_data = &plaintext[4..4 + len];
        self.directory = bincode::deserialize(dir_data)?;

        Ok(())
    }

    fn write_metadata(&mut self) -> Result<()> {
        let data = bincode::serialize(&self.directory)?;
        if data.len() > PAYLOAD_SIZE - 4 {
            bail!("Directory too large for single block (TODO: Implement multi-block directory)");
        }

        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&(data.len() as u32).to_be_bytes());
        plaintext.extend_from_slice(&data);

        let block = prepare_block(&self.key, &plaintext)?;

        self.file.seek(SeekFrom::Start(HEADER_SALT_SIZE as u64))?;
        self.file.write_all(&block)?;
        Ok(())
    }

    fn allocate_block(&mut self) -> Result<u64> {
        self.file.seek(SeekFrom::End(0))?;
        let index = self.total_blocks;
        self.total_blocks += 1;
        Ok(index)
    }

    pub fn write_file(&mut self, filename: &str, data: &[u8]) -> Result<()> {
        let mut blocks = Vec::new();

        for chunk in data.chunks(PAYLOAD_SIZE) {
            let block_data = prepare_block(&self.key, chunk)?;
            let block_idx = self.allocate_block()?;

            let offset = HEADER_SALT_SIZE as u64 + block_idx * BLOCK_SIZE as u64;
            self.file.seek(SeekFrom::Start(offset))?;
            self.file.write_all(&block_data)?;

            blocks.push(block_idx);
        }

        self.directory.files.insert(
            filename.to_string(),
            FileEntry {
                size: data.len() as u64,
                blocks,
            },
        );

        self.write_metadata()?;
        Ok(())
    }

    pub fn read_file(&mut self, filename: &str) -> Result<Vec<u8>> {
        let entry = self
            .directory
            .files
            .get(filename)
            .context("File not found")?
            .clone();

        let mut file_data = Vec::with_capacity(entry.size as usize);

        for &block_idx in &entry.blocks {
            let offset = HEADER_SALT_SIZE as u64 + block_idx * BLOCK_SIZE as u64;
            self.file.seek(SeekFrom::Start(offset))?;
            let mut buf = vec![0u8; BLOCK_SIZE];
            self.file.read_exact(&mut buf)?;

            let plaintext = open_block(&self.key, &buf)?;
            file_data.extend_from_slice(&plaintext);
        }

        file_data.truncate(entry.size as usize);
        Ok(file_data)
    }

    pub fn list_files(&self) -> Vec<String> {
        self.directory.files.keys().cloned().collect()
    }
}
