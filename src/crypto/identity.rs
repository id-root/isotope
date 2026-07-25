use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use anyhow::{Result, Context, bail};
use serde::{Serialize, Deserialize};
use snow::Builder;
use chacha20poly1305::{ChaCha20Poly1305, aead::{Aead, KeyInit}};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::prelude::*;
use blake3::Hasher;

use super::keys::{ZeroizableKeypair, derive_key, derive_nonce};

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    public_hex: String,
    private_hex: String,
    metadata: String,
}

const SALT_LEN: usize = 32;
const SLOT_SIZE: usize = 1024;
const ID_FILE_SIZE: usize = SALT_LEN + 2 * SLOT_SIZE;

pub struct Identity {
    pub keypair: ZeroizableKeypair,
    pub profile_type: String,
}

impl Identity {
    pub fn generate(profile_type: &str) -> Result<Self> {
        let builder = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2b".parse()?);
        let kp = builder.generate_keypair()?;
        Ok(Self {
            keypair: ZeroizableKeypair {
                public: kp.public,
                private: kp.private,
            },
            profile_type: profile_type.to_string(),
        })
    }

    pub fn load<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        if !path.as_ref().exists() {
            bail!("Identity file not found");
        }
        let mut file = File::open(&path)?;
        let mut data = vec![0u8; ID_FILE_SIZE];
        file.read_exact(&mut data).context("Identity file corrupt or too short")?;

        let salt = &data[..SALT_LEN];
        let slot1 = &data[SALT_LEN..SALT_LEN + SLOT_SIZE];
        let slot2 = &data[SALT_LEN + SLOT_SIZE..];

        let key = derive_key(password, salt)?;
        let cipher = ChaCha20Poly1305::new(&key);

        let nonce_slot1 = derive_nonce(password, salt, 0);
        let nonce_slot2 = derive_nonce(password, salt, 1);

        if let Ok(plaintext) = cipher.decrypt(&nonce_slot1, slot1) {
            let len = plaintext.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
            if let Ok(stored) = serde_json::from_slice::<StoredIdentity>(&plaintext[..len]) {
                return Ok(Self {
                    keypair: ZeroizableKeypair {
                        public: hex::decode(stored.public_hex)?,
                        private: hex::decode(stored.private_hex)?,
                    },
                    profile_type: stored.metadata,
                });
            }
        }

        if let Ok(plaintext) = cipher.decrypt(&nonce_slot2, slot2) {
            let len = plaintext.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
            if let Ok(stored) = serde_json::from_slice::<StoredIdentity>(&plaintext[..len]) {
                return Ok(Self {
                    keypair: ZeroizableKeypair {
                        public: hex::decode(stored.public_hex)?,
                        private: hex::decode(stored.private_hex)?,
                    },
                    profile_type: stored.metadata,
                });
            }
        }

        bail!("Invalid password or corrupted identity file");
    }

    pub fn setup_dual<P: AsRef<Path>>(path: P, pass_ops: &str, pass_casual: &str) -> Result<()> {
        let ops_id = Self::generate("ops")?;
        let casual_id = Self::generate("casual")?;

        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let key_ops = derive_key(pass_ops, &salt)?;
        let key_casual = derive_key(pass_casual, &salt)?;

        let ops_stored = StoredIdentity {
            public_hex: hex::encode(&ops_id.keypair.public),
            private_hex: hex::encode(&ops_id.keypair.private),
            metadata: ops_id.profile_type,
        };
        let ops_json = serde_json::to_vec(&ops_stored)?;
        let cipher_ops = ChaCha20Poly1305::new(&key_ops);
        let nonce_ops = derive_nonce(pass_ops, &salt, 0);

        let mut padded_ops = ops_json;
        if padded_ops.len() > 1008 { bail!("Identity too big"); }
        padded_ops.resize(1008, 0);

        let ciphertext_ops = cipher_ops.encrypt(&nonce_ops, padded_ops.as_slice())
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        let casual_stored = StoredIdentity {
            public_hex: hex::encode(&casual_id.keypair.public),
            private_hex: hex::encode(&casual_id.keypair.private),
            metadata: casual_id.profile_type,
        };
        let casual_json = serde_json::to_vec(&casual_stored)?;
        let mut padded_casual = casual_json;
        if padded_casual.len() > 1008 { bail!("Identity too big"); }
        padded_casual.resize(1008, 0);

        let cipher_casual = ChaCha20Poly1305::new(&key_casual);
        let nonce_casual = derive_nonce(pass_casual, &salt, 1);

        let ciphertext_casual = cipher_casual.encrypt(&nonce_casual, padded_casual.as_slice())
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        let mut file = File::create(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }

        file.write_all(&salt)?;
        file.write_all(&ciphertext_ops)?;
        file.write_all(&ciphertext_casual)?;

        Ok(())
    }

    pub fn fingerprint(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(&self.keypair.public);
        BASE64_STANDARD.encode(hasher.finalize().as_bytes())
    }

    pub fn did(&self) -> String {
        let mut bytes = vec![0xec, 0x01];
        bytes.extend_from_slice(&self.keypair.public);
        let multibase = bs58::encode(bytes).into_string();
        format!("did:key:z{}", multibase)
    }
}
