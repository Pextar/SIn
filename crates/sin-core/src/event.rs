//! Minimal nostr event (NIP-01): id derivation and BIP-340 Schnorr signatures.
//!
//! We implement just enough of the event model to verify a sign-in. The event
//! `id` is `sha256` over the canonical array
//! `[0, pubkey, created_at, kind, tags, content]`, and `sig` is a Schnorr
//! signature over that id.

use secp256k1::schnorr::Signature;
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::keys::{Keypair, PublicKey};

/// A nostr event, deserialized straight from its wire JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: i64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl Event {
    /// Compute the canonical id (sha256 of the NIP-01 serialization) for the
    /// current fields, as raw bytes.
    pub fn compute_id(&self) -> [u8; 32] {
        let serialized = serde_json::json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ]);
        // `to_string` on a Value yields compact, no-whitespace JSON, which is
        // exactly the canonical form NIP-01 requires.
        let bytes = serde_json::to_vec(&serialized).expect("json array always serializes");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher.finalize().into()
    }

    /// The signer's public key, parsed from the `pubkey` field.
    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_hex(&self.pubkey)
    }

    /// Return the first value of the first tag whose name matches `name`.
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some(name))
            .and_then(|t| t.get(1))
            .map(String::as_str)
    }

    /// Verify that the stated `id` matches the contents *and* that `sig` is a
    /// valid Schnorr signature over it by `pubkey`.
    pub fn verify(&self) -> Result<()> {
        let computed = self.compute_id();
        let stated = hex::decode(&self.id).map_err(|e| Error::Event(e.to_string()))?;
        if stated.as_slice() != computed {
            return Err(Error::BadEventId);
        }

        let pubkey = self.public_key()?.into_xonly();
        let sig_bytes: [u8; 64] = hex::decode(&self.sig)
            .map_err(|e| Error::Event(e.to_string()))?
            .try_into()
            .map_err(|_| Error::BadSignature)?;
        let sig = Signature::from_byte_array(sig_bytes);

        Secp256k1::verification_only()
            .verify_schnorr(&sig, &computed, &pubkey)
            .map_err(|_| Error::BadSignature)
    }
}

/// Builder used to construct and sign an event. This is primarily a client-side
/// / test helper — the server only ever *verifies* events.
pub struct UnsignedEvent {
    pub created_at: i64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl UnsignedEvent {
    pub fn new(kind: u16, created_at: i64) -> Self {
        Self {
            created_at,
            kind,
            tags: Vec::new(),
            content: String::new(),
        }
    }

    pub fn tag(mut self, values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags.push(values.into_iter().map(Into::into).collect());
        self
    }

    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Finalize: compute the id and sign it with `keypair`.
    pub fn sign(self, keypair: &Keypair) -> Event {
        let mut event = Event {
            id: String::new(),
            pubkey: keypair.public_key().to_hex(),
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags,
            content: self.content,
            sig: String::new(),
        };
        let id = event.compute_id();
        let sig = Secp256k1::new().sign_schnorr(&id, &keypair.signing_keypair());
        event.id = hex::encode(id);
        event.sig = hex::encode(sig.to_byte_array());
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_succeeds() {
        let kp = Keypair::generate();
        let event = UnsignedEvent::new(27235, 1_700_000_000)
            .tag(["u", "https://sockets.local/api/on"])
            .tag(["method", "POST"])
            .sign(&kp);

        assert!(event.verify().is_ok());
        assert_eq!(event.tag("method"), Some("POST"));
        assert_eq!(event.public_key().unwrap(), kp.public_key());
    }

    #[test]
    fn tampered_content_breaks_id() {
        let kp = Keypair::generate();
        let mut event = UnsignedEvent::new(27235, 1_700_000_000)
            .content("on")
            .sign(&kp);
        event.content = "off".into();
        assert!(matches!(event.verify(), Err(Error::BadEventId)));
    }

    #[test]
    fn swapped_signature_is_rejected() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let ev_a = UnsignedEvent::new(27235, 1).sign(&a);
        let mut forged = UnsignedEvent::new(27235, 1).sign(&b);
        // Keep b's id/content but claim a's signature → must fail.
        forged.sig = ev_a.sig;
        assert!(forged.verify().is_err());
    }
}
