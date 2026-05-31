# SIn — passwordless, nostr/bitcoin-style sign-in

No usernames. No passwords. **Your identity is a public key, and you sign in by
signing a challenge.** The server stores only public keys, so there is nothing
to phish, reset, or leak.

Built for internal use (e.g. fronting
[`rf-socket-controller`](https://github.com/Pextar)), on the same secp256k1
crypto that nostr and bitcoin use.

## Why

- **No password database.** The server's entire credential store is a list of
  public keys (`allowlist.json`). A full leak reveals nothing usable.
- **Signatures, not secrets.** The secret key never leaves the signing device.
- **Trivial revocation.** Drop a key from the allowlist to kill access.
- **Reuses the nostr ecosystem.** `npub`/`nsec` encoding (NIP-19), HTTP auth
  (NIP-98), browser signers (NIP-07), and BIP-340 Schnorr signatures.

## How sign-in works

```
client (browser, holds the key)            server (your app + sin-core)
  │                                           │
  │  GET /auth/challenge                      │
  │ ────────────────────────────────────────►│  mint stateless challenge
  │                                           │  (HMAC-stamped, no DB)
  │  ◄──────────────────────────────────────  │
  │                                           │
  │  sign NIP-98 event binding:               │
  │    u=<url>, method=<m>, challenge=<c>      │
  │                                           │
  │  POST <url>                               │
  │    Authorization: Nostr <base64 event>    │
  │ ────────────────────────────────────────►│  Verifier::verify():
  │                                           │    1. Schnorr sig + event id
  │                                           │    2. kind + timestamp skew
  │                                           │    3. url + method match
  │                                           │    4. challenge valid + unspent
  │                                           │    5. pubkey on allowlist
  │  ◄────────── session cookie ────────────  │  issue session, done
```

The **challenge is stateless**: `nonce ‖ expiry ‖ HMAC(server_secret, …)`, so
there's no nonce database — just a small in-memory replay cache to stop a valid
challenge being used twice.

## Crates

| crate / dir | what it is                                                              |
| ----------- | ----------------------------------------------------------------------- |
| `sin-core`  | keypairs + `npub`/`nsec`, nostr events, challenges, allowlist, verifier |
| `sin-cli`   | `sin` — identities, allowlist, plus `challenge` / `verify`              |
| `web/`      | the **signer PWA**: passkey-gated key, NIP-98 signing, installable/offline |

## CLI

```sh
# Generate an identity. Keep the nsec on the device; register the npub.
cargo run -p sin-cli -- gen

# Mint a 32-byte server challenge secret (put it in your server config).
cargo run -p sin-cli -- secret

# Manage the allowlist (trust-on-first-use friendly).
cargo run -p sin-cli -- allow npub1... --label "petter's laptop" --role admin
cargo run -p sin-cli -- list
cargo run -p sin-cli -- revoke npub1...

# Mint and verify tokens (used by the PWA interop test).
cargo run -p sin-cli -- challenge --secret <hex>
echo "Nostr eyJ..." | cargo run -p sin-cli -- verify --secret <hex> --url <url> --method POST
```

## The signer PWA (`web/`)

An installable Progressive Web App that *is* the signer. The secret key is
generated on-device, encrypted with AES-256-GCM, and unlocked only by a passkey
via the **WebAuthn PRF** extension — passwordless, theft-resistant, and the key
never leaves the device. It signs NIP-98 tokens and can drive a SIn-protected
server directly.

```sh
cd web
npm install
npm run build      # bundle into web/dist/ (offline-capable app shell)
npm run dev        # esbuild dev server with live rebuilds
npm run interop    # sign tokens in JS, verify them with the Rust `sin` CLI
```

> Passkey unlock requires a real browser with WebAuthn PRF support (current
> Chrome, Safari 18+). Serve over HTTPS (or `localhost`) and over a stable
> origin, since passkeys and IndexedDB are bound to the origin.

## Using it from a server

```rust
use sin_core::{Allowlist, ChallengeKey, Verifier};

let allowlist = Allowlist::load("allowlist.json")?;
let challenge = ChallengeKey::new(server_secret_bytes, 300); // 5-min TTL
let verifier = Verifier::new(challenge, 60);                 // 60s clock skew

// GET /auth/challenge
let challenge_str = verifier.issue_challenge(now_unix);

// On a protected route, with the request's Authorization header:
let signin = verifier.verify(&auth_header, "POST", &request_url, &allowlist, now_unix)?;
println!("authenticated {} as {}", signin.label, signin.role);
```

## Status / roadmap

- [x] `sin-core`: keys, NIP-19, NIP-98 verification, stateless challenges, replay
      cache, allowlist
- [x] `sin-cli`: identity + allowlist management, plus `challenge` / `verify`
- [x] **signer PWA** (`web/`): on-device keypair, passkey-gated via WebAuthn PRF,
      NIP-98 signing, installable/offline, JS↔Rust interop-tested
- [ ] `sin-middleware`: drop-in `axum` extractor (`require_signin()`) + a demo
      server exposing `/auth/challenge` and a protected route
- [ ] `examples/rf-socket`: wired into rf-socket-controller
- [ ] session issuance (signed cookie / JWT) after a successful sign-in

## Security notes

- The in-browser key is encrypted at rest (AES-256-GCM) and unlocked with a
  passkey (WebAuthn PRF) — passwordless but theft-resistant.
- The replay cache is process-local; for multi-instance deployments back it with
  a shared store.
- Losing a device means losing that identity — by design. Re-enrolling is one
  `sin allow` away.

## License

MIT
