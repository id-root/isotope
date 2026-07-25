use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Noise handshake failed: {0}")]
    NoiseHandshakeFailed(String),

    #[error("Post-quantum key exchange failed")]
    PqExchangeFailed,

    #[error("PQ decryption failed — data integrity check failed")]
    PqDecryptionFailed,

    #[error("Identity file not found at path: {0}")]
    IdentityNotFound(String),

    #[error("Invalid identity password or corrupted identity file")]
    InvalidIdentityPassword,

    #[error("Identity payload exceeds maximum slot capacity")]
    IdentitySlotOverflow,

    #[error("Argon2 key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Session lock poisoned")]
    SessionLockPoisoned,
}
