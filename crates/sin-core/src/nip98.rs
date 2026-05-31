//! NIP-98 HTTP authentication, extended with a SIn challenge binding.
//!
//! The client signs a kind-`27235` event whose tags bind the request to a
//! specific URL, method, and server-issued challenge, then sends it in the
//! header:
//!
//! ```text
//! Authorization: Nostr <base64(event-json)>
//! ```
//!
//! The server verifies the signature, that the URL/method match the actual
//! request, that the embedded challenge is one it minted and hasn't expired,
//! and that the challenge hasn't already been spent.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::allowlist::Allowlist;
use crate::error::{Error, Result};
use crate::event::Event;
use crate::keys::PublicKey;
use crate::nonce::ChallengeKey;
use crate::replay::ReplayCache;

/// NIP-98 HTTP Auth event kind.
pub const KIND_HTTP_AUTH: u16 = 27235;

const AUTH_SCHEME: &str = "Nostr";

/// The tag name used to bind a SIn challenge into the signed event.
pub const CHALLENGE_TAG: &str = "challenge";

/// Outcome of a successful sign-in.
#[derive(Debug, Clone)]
pub struct SignIn {
    /// The authenticated identity.
    pub pubkey: PublicKey,
    /// Role from the allowlist entry (e.g. "admin", "user").
    pub role: String,
    /// Label from the allowlist entry.
    pub label: String,
}

/// Verifies NIP-98 sign-in requests against a challenge key and replay cache.
pub struct Verifier {
    challenge: ChallengeKey,
    replay: ReplayCache,
    /// Allowed clock skew between the event's `created_at` and server time.
    max_skew_secs: i64,
}

impl Verifier {
    /// Create a verifier. `max_skew_secs` bounds how far the event timestamp
    /// may drift from server time (a typical value is 60).
    pub fn new(challenge: ChallengeKey, max_skew_secs: i64) -> Self {
        Self {
            challenge,
            replay: ReplayCache::new(),
            max_skew_secs,
        }
    }

    /// Mint a fresh challenge for a client to sign.
    pub fn issue_challenge(&self, now_unix: u64) -> String {
        self.challenge.issue(now_unix)
    }

    /// Verify an `Authorization` header value against the actual request.
    ///
    /// * `header` — the full header value, e.g. `Nostr eyJ...`.
    /// * `method` — the HTTP method of the request being authorized.
    /// * `url` — the absolute URL of the request being authorized.
    /// * `allowlist` — permitted public keys.
    /// * `now_unix` — current server time.
    pub fn verify(
        &self,
        header: &str,
        method: &str,
        url: &str,
        allowlist: &Allowlist,
        now_unix: u64,
    ) -> Result<SignIn> {
        let event = parse_header(header)?;

        // 1. Cryptographic integrity: id matches contents and sig is valid.
        event.verify()?;

        // 2. Structural policy: right kind, fresh timestamp.
        if event.kind != KIND_HTTP_AUTH {
            return Err(Error::Unauthorized(format!(
                "expected kind {KIND_HTTP_AUTH}, got {}",
                event.kind
            )));
        }
        let skew = (event.created_at - now_unix as i64).abs();
        if skew > self.max_skew_secs {
            return Err(Error::Unauthorized("timestamp outside allowed skew".into()));
        }

        // 3. Request binding: the signed URL and method must match this request.
        match event.tag("u") {
            Some(u) if u == url => {}
            Some(_) => return Err(Error::Unauthorized("url mismatch".into())),
            None => return Err(Error::Unauthorized("missing u tag".into())),
        }
        match event.tag("method") {
            Some(m) if m.eq_ignore_ascii_case(method) => {}
            Some(_) => return Err(Error::Unauthorized("method mismatch".into())),
            None => return Err(Error::Unauthorized("missing method tag".into())),
        }

        // 4. Challenge binding: must be one we issued, unexpired, and unspent.
        let challenge = event
            .tag(CHALLENGE_TAG)
            .ok_or_else(|| Error::Unauthorized("missing challenge tag".into()))?;
        let (nonce, expiry) = self.challenge.verify(challenge, now_unix)?;
        if !self.replay.check_and_record(nonce, expiry, now_unix) {
            return Err(Error::Unauthorized("challenge already used".into()));
        }

        // 5. Authorization: the key must be on the allowlist.
        let pubkey = event.public_key()?;
        let entry = allowlist.entry(&pubkey).ok_or(Error::NotAllowed)?;

        Ok(SignIn {
            pubkey,
            role: entry.role.clone(),
            label: entry.label.clone(),
        })
    }
}

/// Parse an `Authorization: Nostr <base64>` header value into an [`Event`].
pub fn parse_header(header: &str) -> Result<Event> {
    let rest = header
        .strip_prefix(AUTH_SCHEME)
        .map(str::trim_start)
        .ok_or_else(|| Error::Unauthorized("not a Nostr authorization header".into()))?;
    let json = STANDARD
        .decode(rest.trim())
        .map_err(|_| Error::Unauthorized("authorization payload is not base64".into()))?;
    let event: Event = serde_json::from_slice(&json)
        .map_err(|e| Error::Unauthorized(format!("authorization payload is not an event: {e}")))?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::UnsignedEvent;
    use crate::keys::Keypair;

    const URL: &str = "https://sockets.local/api/socket/3/on";
    const METHOD: &str = "POST";

    fn setup() -> (Verifier, Allowlist, Keypair) {
        let challenge = ChallengeKey::new(*b"server-secret-for-nip98-tests-01", 300);
        let verifier = Verifier::new(challenge, 60);
        let kp = Keypair::generate();
        let mut allowlist = Allowlist::new();
        allowlist.allow(&kp.public_key(), "tester", "admin");
        (verifier, allowlist, kp)
    }

    fn make_header(kp: &Keypair, url: &str, method: &str, challenge: &str, now: i64) -> String {
        let event = UnsignedEvent::new(KIND_HTTP_AUTH, now)
            .tag(["u", url])
            .tag(["method", method])
            .tag([CHALLENGE_TAG, challenge])
            .sign(kp);
        let json = serde_json::to_vec(&event).unwrap();
        format!("Nostr {}", STANDARD.encode(json))
    }

    #[test]
    fn happy_path() {
        let (v, allow, kp) = setup();
        let now = 1_700_000_000;
        let challenge = v.issue_challenge(now as u64);
        let header = make_header(&kp, URL, METHOD, &challenge, now);

        let signin = v.verify(&header, METHOD, URL, &allow, now as u64).unwrap();
        assert_eq!(signin.pubkey, kp.public_key());
        assert_eq!(signin.role, "admin");
    }

    #[test]
    fn replayed_challenge_rejected() {
        let (v, allow, kp) = setup();
        let now = 1_700_000_000u64;
        let challenge = v.issue_challenge(now);
        let header = make_header(&kp, URL, METHOD, &challenge, now as i64);

        assert!(v.verify(&header, METHOD, URL, &allow, now).is_ok());
        // Same signed event again → replay cache must reject.
        let err = v.verify(&header, METHOD, URL, &allow, now).unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn url_mismatch_rejected() {
        let (v, allow, kp) = setup();
        let now = 1_700_000_000u64;
        let challenge = v.issue_challenge(now);
        let header = make_header(&kp, URL, METHOD, &challenge, now as i64);
        let err = v
            .verify(&header, METHOD, "https://evil.local/api", &allow, now)
            .unwrap_err();
        assert!(matches!(err, Error::Unauthorized(_)));
    }

    #[test]
    fn unknown_key_rejected() {
        let (v, _allow, kp) = setup();
        let empty = Allowlist::new();
        let now = 1_700_000_000u64;
        let challenge = v.issue_challenge(now);
        let header = make_header(&kp, URL, METHOD, &challenge, now as i64);
        let err = v.verify(&header, METHOD, URL, &empty, now).unwrap_err();
        assert!(matches!(err, Error::NotAllowed));
    }

    #[test]
    fn forged_challenge_rejected() {
        let (v, allow, kp) = setup();
        let now = 1_700_000_000u64;
        let header = make_header(&kp, URL, METHOD, "not-a-real-challenge", now as i64);
        let err = v.verify(&header, METHOD, URL, &allow, now).unwrap_err();
        assert!(matches!(err, Error::Challenge(_)));
    }
}
