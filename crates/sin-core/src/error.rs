use thiserror::Error;

/// Errors produced while generating keys, parsing events, or verifying a sign-in.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid key material: {0}")]
    Key(String),

    #[error("bech32 encoding error: {0}")]
    Bech32(String),

    #[error("malformed nostr event: {0}")]
    Event(String),

    #[error("signature verification failed")]
    BadSignature,

    #[error("event id does not match its contents")]
    BadEventId,

    /// The NIP-98 event was structurally valid but failed a policy check
    /// (wrong kind, URL mismatch, method mismatch, stale timestamp, ...).
    #[error("authorization rejected: {0}")]
    Unauthorized(String),

    /// The signing key is valid but not on the server's allowlist.
    #[error("public key is not allowed")]
    NotAllowed,

    #[error("invalid or expired challenge: {0}")]
    Challenge(String),

    #[error("invalid or expired session: {0}")]
    Session(String),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
