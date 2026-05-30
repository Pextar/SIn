//! A tiny in-memory replay cache.
//!
//! Stateless challenges (see [`crate::nonce`]) are valid for their whole TTL,
//! so a captured-but-valid challenge could be replayed until it expires. This
//! cache records spent nonces until their expiry and rejects repeats. It is
//! deliberately process-local; for multi-instance deployments back it with a
//! shared store (Redis, etc.) instead.

use std::collections::HashMap;
use std::sync::Mutex;

/// Records spent nonces and rejects repeats until they expire.
#[derive(Default)]
pub struct ReplayCache {
    seen: Mutex<HashMap<[u8; 16], u64>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a nonce as spent. Returns `true` if it was fresh, `false` if it
    /// had already been used (i.e. a replay). `expiry_unix` lets the entry be
    /// pruned once the underlying challenge can no longer be valid anyway.
    pub fn check_and_record(&self, nonce: [u8; 16], expiry_unix: u64, now_unix: u64) -> bool {
        let mut seen = self.seen.lock().expect("replay cache mutex poisoned");
        seen.retain(|_, exp| *exp > now_unix);
        if seen.contains_key(&nonce) {
            return false;
        }
        seen.insert(nonce, expiry_unix);
        true
    }

    /// Number of currently-tracked nonces (mainly for tests/metrics).
    pub fn len(&self) -> usize {
        self.seen.lock().expect("replay cache mutex poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_ok_second_use_rejected() {
        let cache = ReplayCache::new();
        let nonce = [7u8; 16];
        assert!(cache.check_and_record(nonce, 100, 10));
        assert!(!cache.check_and_record(nonce, 100, 10));
    }

    #[test]
    fn expired_entries_are_pruned() {
        let cache = ReplayCache::new();
        cache.check_and_record([1u8; 16], 50, 10);
        assert_eq!(cache.len(), 1);
        // A later check past expiry prunes the old entry.
        cache.check_and_record([2u8; 16], 200, 100);
        assert_eq!(cache.len(), 1);
    }
}
