use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Password does not meet requirements: {0}")]
    WeakPassword(&'static str),

    #[error("Vault file too short or corrupted")]
    CorruptedVault,

    #[error("Block capacity exceeded: data size {0} > max {1}")]
    BlockOverflow(usize, usize),

    #[error("Block index {0} out of bounds")]
    BlockOutOfBounds(u64),

    #[error("File not found in vault: {0}")]
    FileNotFound(String),

    #[error("Directory structure too large for single metadata block")]
    DirectoryOverflow,

    #[error("Hidden vault requires at least {0} blocks")]
    InsufficientBlocks(u64),

    #[error("Vault file already exists at path")]
    AlreadyExists,

    #[error("Decryption failed — invalid password or corrupted data")]
    DecryptionFailed,
}
