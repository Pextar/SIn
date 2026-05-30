//! The set of public keys permitted to sign in.
//!
//! This is the *entire* server-side credential store: a list of public keys.
//! There are no secrets here, so it is safe to keep in a plain JSON file under
//! version control or config management.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::keys::PublicKey;

/// A single permitted identity plus a human label and role.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Friendly name, e.g. "petter's laptop".
    pub label: String,
    /// Free-form role string the application can authorize against.
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "user".to_string()
}

/// An allowlist keyed by lowercase hex public key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Allowlist {
    #[serde(default)]
    keys: BTreeMap<String, Entry>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from a JSON file. A missing file yields an empty allowlist so that
    /// first-run / trust-on-first-use flows work.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        match std::fs::read(path.as_ref()) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Persist to a JSON file (pretty-printed for easy hand-editing).
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Is this key permitted?
    pub fn contains(&self, key: &PublicKey) -> bool {
        self.keys.contains_key(&key.to_hex())
    }

    /// Look up the entry for a key, if present.
    pub fn entry(&self, key: &PublicKey) -> Option<&Entry> {
        self.keys.get(&key.to_hex())
    }

    /// Add or replace an entry. Returns the previous entry, if any.
    pub fn allow(&mut self, key: &PublicKey, label: impl Into<String>, role: impl Into<String>) -> Option<Entry> {
        self.keys.insert(
            key.to_hex(),
            Entry {
                label: label.into(),
                role: role.into(),
            },
        )
    }

    /// Remove a key. Returns true if it was present.
    pub fn revoke(&mut self, key: &PublicKey) -> bool {
        self.keys.remove(&key.to_hex()).is_some()
    }

    /// True if no keys are registered yet (used for trust-on-first-use).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Iterate over `(PublicKey, &Entry)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (PublicKey, &Entry)> {
        self.keys
            .iter()
            .filter_map(|(hex, entry)| PublicKey::from_hex(hex).ok().map(|pk| (pk, entry)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Keypair;

    #[test]
    fn allow_contains_revoke() {
        let mut list = Allowlist::new();
        let pk = Keypair::generate().public_key();
        assert!(list.is_empty());
        assert!(!list.contains(&pk));

        list.allow(&pk, "laptop", "admin");
        assert!(list.contains(&pk));
        assert_eq!(list.entry(&pk).unwrap().role, "admin");

        assert!(list.revoke(&pk));
        assert!(!list.contains(&pk));
        assert!(!list.revoke(&pk));
    }

    #[test]
    fn json_roundtrip() {
        let mut list = Allowlist::new();
        let pk = Keypair::generate().public_key();
        list.allow(&pk, "laptop", "user");
        let json = serde_json::to_string(&list).unwrap();
        let back: Allowlist = serde_json::from_str(&json).unwrap();
        assert!(back.contains(&pk));
    }
}
