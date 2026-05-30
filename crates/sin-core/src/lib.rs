//! # sin-core
//!
//! Passwordless, nostr/bitcoin-style sign-in primitives.
//!
//! An identity is a secp256k1 (BIP-340 / nostr) keypair. To sign in, a client
//! signs a [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md)
//! HTTP-auth event that binds the request URL, method, and a server-issued
//! challenge. The server stores only *public* keys — there are no passwords and
//! no secrets in its credential store.
//!
//! ## Pieces
//!
//! * [`Keypair`] / [`PublicKey`] — key generation and `npub`/`nsec` encoding.
//! * [`Event`] / [`UnsignedEvent`] — minimal nostr event with Schnorr sign/verify.
//! * [`ChallengeKey`] — stateless, self-authenticating challenges.
//! * [`ReplayCache`] — rejects a valid challenge being used twice.
//! * [`Allowlist`] — the set of permitted public keys.
//! * [`Verifier`] — puts it together to authenticate a NIP-98 request.
//!
//! ## Server sketch
//!
//! ```no_run
//! use sin_core::{Allowlist, ChallengeKey, Verifier};
//!
//! // Load config once at startup.
//! let allowlist = Allowlist::load("allowlist.json").unwrap();
//! let challenge = ChallengeKey::new(*b"a-32-byte-per-deployment-secret!", 300);
//! let verifier = Verifier::new(challenge, 60);
//!
//! // GET /auth/challenge
//! let now = 1_700_000_000;
//! let challenge_str = verifier.issue_challenge(now);
//!
//! // ... client signs it and calls a protected route with an Authorization header ...
//! let header = "Nostr eyJ...";
//! match verifier.verify(header, "POST", "https://sockets.local/api/on", &allowlist, now) {
//!     Ok(signin) => println!("hello {} ({})", signin.label, signin.role),
//!     Err(e) => eprintln!("denied: {e}"),
//! }
//! ```

mod allowlist;
mod error;
mod event;
mod keys;
mod nip98;
mod nonce;
mod replay;

pub use allowlist::{Allowlist, Entry};
pub use error::{Error, Result};
pub use event::{Event, UnsignedEvent};
pub use keys::{Keypair, PublicKey};
pub use nip98::{parse_header, SignIn, Verifier, CHALLENGE_TAG, KIND_HTTP_AUTH};
pub use nonce::ChallengeKey;
pub use replay::ReplayCache;
