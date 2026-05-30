//! Stateless challenges.
//!
//! The server hands the client a random challenge to sign. To avoid keeping a
//! database of outstanding nonces, we make the challenge self-authenticating:
//!
//! ```text
//! challenge = base64url( nonce[16] || expiry_unix_be[8] || HMAC-SHA256(key, nonce || expiry) )
//! ```
//!
//! On the way back in we recompute the HMAC and check the expiry. A small
//! replay cache (see [`crate::replay`]) stops a valid challenge being reused
//! within its lifetime.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 16;
const EXPIRY_LEN: usize = 8;
const TAG_LEN: usize = 32;
const TOTAL_LEN: usize = NONCE_LEN + EXPIRY_LEN + TAG_LEN;

/// Issues and verifies stateless challenges, keyed by a server secret.
///
/// The `secret` should be a random per-deployment value (e.g. 32 bytes) kept
/// only on the server. Rotating it invalidates all outstanding challenges.
#[derive(Clone)]
pub struct ChallengeKey {
    secret: Vec<u8>,
    ttl_secs: u64,
}

impl ChallengeKey {
    /// Create a challenge signer with the given secret and time-to-live.
    pub fn new(secret: impl Into<Vec<u8>>, ttl_secs: u64) -> Self {
        Self {
            secret: secret.into(),
            ttl_secs,
        }
    }

    /// Mint a fresh challenge that expires `ttl_secs` after `now_unix`.
    pub fn issue(&self, now_unix: u64) -> String {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let expiry = now_unix.saturating_add(self.ttl_secs);

        let mut buf = Vec::with_capacity(TOTAL_LEN);
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&expiry.to_be_bytes());
        buf.extend_from_slice(&self.tag(&nonce, expiry));
        URL_SAFE_NO_PAD.encode(buf)
    }

    /// Verify a challenge string: checks the HMAC then the expiry. On success
    /// returns the 16-byte nonce (a replay-cache key) and the challenge's
    /// expiry timestamp.
    pub fn verify(&self, challenge: &str, now_unix: u64) -> Result<([u8; NONCE_LEN], u64)> {
        let raw = URL_SAFE_NO_PAD
            .decode(challenge.trim())
            .map_err(|_| Error::Challenge("not valid base64url".into()))?;
        if raw.len() != TOTAL_LEN {
            return Err(Error::Challenge("wrong length".into()));
        }

        let nonce: [u8; NONCE_LEN] = raw[..NONCE_LEN].try_into().unwrap();
        let expiry_bytes: [u8; EXPIRY_LEN] = raw[NONCE_LEN..NONCE_LEN + EXPIRY_LEN]
            .try_into()
            .unwrap();
        let tag = &raw[NONCE_LEN + EXPIRY_LEN..];
        let expiry = u64::from_be_bytes(expiry_bytes);

        // Constant-time tag check before we trust any field.
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac accepts any key length");
        mac.update(&nonce);
        mac.update(&expiry.to_be_bytes());
        mac.verify_slice(tag)
            .map_err(|_| Error::Challenge("bad signature".into()))?;

        if now_unix > expiry {
            return Err(Error::Challenge("expired".into()));
        }
        Ok((nonce, expiry))
    }

    fn tag(&self, nonce: &[u8], expiry: u64) -> [u8; TAG_LEN] {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac accepts any key length");
        mac.update(nonce);
        mac.update(&expiry.to_be_bytes());
        mac.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ChallengeKey {
        ChallengeKey::new(*b"this-is-a-test-server-secret-0001", 300)
    }

    #[test]
    fn fresh_challenge_verifies() {
        let k = key();
        let now = 1_700_000_000;
        let c = k.issue(now);
        let (_nonce, expiry) = k.verify(&c, now + 10).unwrap();
        assert_eq!(expiry, now + 300);
    }

    #[test]
    fn expired_challenge_rejected() {
        let k = key();
        let now = 1_700_000_000;
        let c = k.issue(now);
        assert!(matches!(
            k.verify(&c, now + 301),
            Err(Error::Challenge(_))
        ));
    }

    #[test]
    fn tampering_breaks_the_tag() {
        let k = key();
        let now = 1_700_000_000;
        let c = k.issue(now);
        let mut raw = URL_SAFE_NO_PAD.decode(&c).unwrap();
        raw[0] ^= 0xff; // flip a nonce bit
        let forged = URL_SAFE_NO_PAD.encode(raw);
        assert!(k.verify(&forged, now + 10).is_err());
    }

    #[test]
    fn wrong_secret_rejects() {
        let now = 1_700_000_000;
        let c = key().issue(now);
        let other = ChallengeKey::new(*b"a-completely-different-secret-key", 300);
        assert!(other.verify(&c, now + 10).is_err());
    }
}
