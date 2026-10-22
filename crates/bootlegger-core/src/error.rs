use thiserror::Error;

#[derive(Error, Debug)]
pub enum BootlegError {
    #[error("Carrier capacity insufficient: secret requires {needed_bytes} bytes, but carrier only provides {available_bytes} safe stealth bytes (need at least {additional_files_needed} more files)")]
    InsufficientCapacity {
        needed_bytes: usize,
        available_bytes: usize,
        additional_files_needed: usize,
    },

    #[error("Carrier integrity compromised (Tripwire Triggered): {0}")]
    TamperDetected(String),

    #[error("Authentication failed: invalid password or corrupted data")]
    AuthenticationFailed,

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, BootlegError>;
