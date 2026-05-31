//! Stateless session tokens.
//!
//! A NIP-98 sign-in proves identity for a single request. Re-signing on every
//! call is fine for a CLI, but a browser wants to authenticate once and then
//! make many calls. After a successful [`crate::Verifier::verify`], the server
//! mints a *session token* that carries the already-verified identity, signed
//! with a server secret so it can't be forged:
//!
//! ```text
//! token = base64url(payload-json) "." base64url(HMAC-SHA256(key, payload-json))
//! ```
//!
//! Like [`crate::ChallengeKey`], this keeps the server stateless — there is no
//! session table. The token is self-contained and self-authenticating; rotating
//! the secret invalidates every outstanding session.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::keys::PublicKey;

type HmacSha256 = Hmac<Sha256>;

/// A verified session, recovered from a token.
#[derive(Debug, Clone)]
pub struct Session {
    /// The authenticated identity.
    pub pubkey: PublicKey,
    /// Role carried over from the allowlist entry at sign-in time.
    pub role: String,
    /// Label carried over from the allowlist entry at sign-in time.
    pub label: String,
    /// When the session was issued (unix seconds).
    pub issued_at: u64,
    /// When the session expires (unix seconds).
    pub expires_at: u64,
}

/// The wire payload. Kept compact; field names are short because they ride in a
/// cookie on every request.
#[derive(Serialize, Deserialize)]
struct Payload {
    /// Public key, lowercase hex.
    pk: String,
    role: String,
    label: String,
    /// Issued-at (unix seconds).
    iat: u64,
    /// Expiry (unix seconds).
    exp: u64,
}

/// Mints and verifies stateless session tokens, keyed by a server secret.
///
/// Use a random per-deployment secret (e.g. 32 bytes). It can be the same kind
/// of secret as [`crate::ChallengeKey`] but should be a *distinct* value so the
/// two token types can't be confused.
#[derive(Clone)]
pub struct SessionKey {
    secret: Vec<u8>,
    ttl_secs: u64,
}

impl SessionKey {
    /// Create a session signer with the given secret and lifetime.
    pub fn new(secret: impl Into<Vec<u8>>, ttl_secs: u64) -> Self {
        Self {
            secret: secret.into(),
            ttl_secs,
        }
    }

    /// How long minted sessions live, in seconds (useful for a cookie `Max-Age`).
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Mint a session token for an authenticated identity.
    pub fn issue(&self, pubkey: &PublicKey, role: &str, label: &str, now_unix: u64) -> String {
        let payload = Payload {
            pk: pubkey.to_hex(),
            role: role.to_string(),
            label: label.to_string(),
            iat: now_unix,
            exp: now_unix.saturating_add(self.ttl_secs),
        };
        // Serializing our own fixed struct cannot fail.
        let body = serde_json::to_vec(&payload).expect("session payload always serializes");
        let tag = self.tag(&body);
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&body),
            URL_SAFE_NO_PAD.encode(tag)
        )
    }

    /// Verify a session token: checks the HMAC, then the expiry, and recovers
    /// the [`Session`]. Returns [`Error::Session`] on any failure.
    pub fn verify(&self, token: &str, now_unix: u64) -> Result<Session> {
        let (body_b64, tag_b64) = token
            .trim()
            .split_once('.')
            .ok_or_else(|| Error::Session("malformed token".into()))?;
        let body = URL_SAFE_NO_PAD
            .decode(body_b64)
            .map_err(|_| Error::Session("payload is not base64url".into()))?;
        let tag = URL_SAFE_NO_PAD
            .decode(tag_b64)
            .map_err(|_| Error::Session("signature is not base64url".into()))?;

        // Constant-time tag check before we trust any field.
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac accepts any key length");
        mac.update(&body);
        mac.verify_slice(&tag)
            .map_err(|_| Error::Session("bad signature".into()))?;

        let payload: Payload =
            serde_json::from_slice(&body).map_err(|_| Error::Session("payload is not json".into()))?;
        if now_unix > payload.exp {
            return Err(Error::Session("expired".into()));
        }
        let pubkey = PublicKey::from_hex(&payload.pk)
            .map_err(|_| Error::Session("payload has an invalid public key".into()))?;

        Ok(Session {
            pubkey,
            role: payload.role,
            label: payload.label,
            issued_at: payload.iat,
            expires_at: payload.exp,
        })
    }

    fn tag(&self, body: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac accepts any key length");
        mac.update(body);
        mac.finalize().into_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    fn key() -> SessionKey {
        SessionKey::new(*b"this-is-a-test-session-secret-01", 3600)
    }

    #[test]
    fn issued_session_verifies_and_roundtrips() {
        let k = key();
        let pk = Keypair::generate().public_key();
        let now = 1_700_000_000;
        let token = k.issue(&pk, "admin", "petter's laptop", now);

        let s = k.verify(&token, now + 10).unwrap();
        assert_eq!(s.pubkey, pk);
        assert_eq!(s.role, "admin");
        assert_eq!(s.label, "petter's laptop");
        assert_eq!(s.expires_at, now + 3600);
    }

    #[test]
    fn expired_session_rejected() {
        let k = key();
        let pk = Keypair::generate().public_key();
        let now = 1_700_000_000;
        let token = k.issue(&pk, "user", "phone", now);
        assert!(matches!(
            k.verify(&token, now + 3601),
            Err(Error::Session(_))
        ));
    }

    #[test]
    fn tampering_breaks_the_tag() {
        let k = key();
        let pk = Keypair::generate().public_key();
        let now = 1_700_000_000;
        let token = k.issue(&pk, "user", "phone", now);

        // Forge an elevated role in the payload while keeping the old tag.
        let (_body, tag) = token.split_once('.').unwrap();
        let forged_body = Payload {
            pk: pk.to_hex(),
            role: "admin".into(),
            label: "phone".into(),
            iat: now,
            exp: now + 3600,
        };
        let body = serde_json::to_vec(&forged_body).unwrap();
        let forged = format!("{}.{}", URL_SAFE_NO_PAD.encode(body), tag);
        assert!(k.verify(&forged, now + 10).is_err());
    }

    #[test]
    fn wrong_secret_rejects() {
        let pk = Keypair::generate().public_key();
        let now = 1_700_000_000;
        let token = key().issue(&pk, "user", "phone", now);
        let other = SessionKey::new(*b"a-completely-different-secret-key", 3600);
        assert!(matches!(other.verify(&token, now + 10), Err(Error::Session(_))));
    }

    #[test]
    fn malformed_token_rejected() {
        let k = key();
        assert!(k.verify("not-a-token", 1_700_000_000).is_err());
        assert!(k.verify("only-one-part.", 1_700_000_000).is_err());
    }
}
