//! secp256k1 keypairs with nostr-style `npub`/`nsec` (NIP-19) encoding.
//!
//! An identity in SIn *is* an x-only public key (BIP-340 / nostr). The server
//! only ever stores the public half; the secret never leaves the signer.

use bech32::{Bech32, Hrp};
use secp256k1::{Keypair as SecpKeypair, Secp256k1, SecretKey, XOnlyPublicKey};

use crate::error::{Error, Result};

const HRP_NPUB: &str = "npub";
const HRP_NSEC: &str = "nsec";

/// A public identity: a 32-byte x-only secp256k1 key, as used by nostr and
/// bitcoin taproot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub(crate) XOnlyPublicKey);

impl PublicKey {
    /// Parse from 32 bytes of x-only key material.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Key("public key must be 32 bytes".into()))?;
        XOnlyPublicKey::from_byte_array(array)
            .map(PublicKey)
            .map_err(|e| Error::Key(e.to_string()))
    }

    /// Parse from 64 hex characters.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim()).map_err(|e| Error::Key(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Parse from a bech32 `npub1...` string (NIP-19).
    pub fn from_npub(npub: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(npub.trim()).map_err(|e| Error::Bech32(e.to_string()))?;
        if hrp.as_str() != HRP_NPUB {
            return Err(Error::Bech32(format!("expected npub, got {}", hrp.as_str())));
        }
        Self::from_bytes(&data)
    }

    /// The raw 32-byte x-only representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.serialize()
    }

    /// Lowercase 64-character hex (the nostr event `pubkey` field).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Human-facing `npub1...` encoding (NIP-19).
    pub fn to_npub(&self) -> String {
        encode_bech32(HRP_NPUB, &self.to_bytes())
    }

    /// The underlying libsecp x-only key.
    pub(crate) fn into_xonly(self) -> XOnlyPublicKey {
        self.0
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.to_npub())
    }
}

/// A full keypair. This is the *signer's* secret; it should only live on the
/// client device, never on the server.
pub struct Keypair {
    secret: SecretKey,
    public: PublicKey,
}

impl Keypair {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (secret, _) = secp.generate_keypair(&mut secp256k1::rand::rng());
        Self::from_secret(secret)
    }

    /// Reconstruct from a 32-byte secret.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Key("secret key must be 32 bytes".into()))?;
        let secret = SecretKey::from_byte_array(array).map_err(|e| Error::Key(e.to_string()))?;
        Ok(Self::from_secret(secret))
    }

    /// Reconstruct from 64 hex characters.
    pub fn from_secret_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim()).map_err(|e| Error::Key(e.to_string()))?;
        Self::from_secret_bytes(&bytes)
    }

    /// Reconstruct from a bech32 `nsec1...` string (NIP-19).
    pub fn from_nsec(nsec: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(nsec.trim()).map_err(|e| Error::Bech32(e.to_string()))?;
        if hrp.as_str() != HRP_NSEC {
            return Err(Error::Bech32(format!("expected nsec, got {}", hrp.as_str())));
        }
        Self::from_secret_bytes(&data)
    }

    fn from_secret(secret: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let keypair = SecpKeypair::from_secret_key(&secp, &secret);
        let (xonly, _parity) = keypair.x_only_public_key();
        Self {
            secret,
            public: PublicKey(xonly),
        }
    }

    /// The public identity to register on the server.
    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Raw 32-byte secret. Handle with care.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.secret_bytes()
    }

    /// Human-facing `nsec1...` encoding (NIP-19). Treat as a password-equivalent.
    pub fn to_nsec(&self) -> String {
        encode_bech32(HRP_NSEC, &self.secret_bytes())
    }

    /// Internal: the libsecp keypair used for signing.
    pub(crate) fn signing_keypair(&self) -> SecpKeypair {
        SecpKeypair::from_secret_key(&Secp256k1::new(), &self.secret)
    }
}

fn encode_bech32(hrp: &str, data: &[u8]) -> String {
    // HRPs here are compile-time constants known to be valid bech32 HRPs,
    // and 32 bytes is always within the bech32 length budget, so this cannot
    // fail in practice.
    let hrp = Hrp::parse(hrp).expect("static hrp is valid");
    bech32::encode::<Bech32>(hrp, data).expect("32-byte payload always encodes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_roundtrips_through_hex_and_bech32() {
        let kp = Keypair::generate();
        let pk = kp.public_key();

        // hex roundtrip
        let from_hex = PublicKey::from_hex(&pk.to_hex()).unwrap();
        assert_eq!(pk, from_hex);

        // npub roundtrip
        let from_npub = PublicKey::from_npub(&pk.to_npub()).unwrap();
        assert_eq!(pk, from_npub);

        // nsec roundtrip preserves the public key
        let from_nsec = Keypair::from_nsec(&kp.to_nsec()).unwrap();
        assert_eq!(pk, from_nsec.public_key());
    }

    #[test]
    fn npub_has_expected_shape() {
        let kp = Keypair::generate();
        let npub = kp.public_key().to_npub();
        assert!(npub.starts_with("npub1"));
        assert!(kp.to_nsec().starts_with("nsec1"));
    }

    #[test]
    fn known_nip19_vector() {
        // Vector from NIP-19.
        let hex = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let pk = PublicKey::from_hex(hex).unwrap();
        assert_eq!(
            pk.to_npub(),
            "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
        );
        assert_eq!(
            PublicKey::from_npub(
                "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
            )
            .unwrap(),
            pk
        );
    }

    #[test]
    fn rejects_wrong_hrp() {
        let kp = Keypair::generate();
        // Feeding an nsec where an npub is expected must fail.
        assert!(PublicKey::from_npub(&kp.to_nsec()).is_err());
    }
}
