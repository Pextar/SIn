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

### Sign once: sessions

Signing every request is right for a CLI, but a browser wants to authenticate
once. After a successful sign-in to `POST /auth/login`, the server mints a
**session token** and sets it as an `HttpOnly` cookie. Subsequent calls are
authorized by that cookie alone — no further signing until it expires.

The session token is stateless too, mirroring the challenge:
`base64url(payload) ‖ HMAC(session_secret, payload)`, carrying the verified
pubkey/role/label and an expiry. So there's **no session table either** —
rotating the secret invalidates every session. The token also works as an
`Authorization: Bearer <token>` header for non-browser clients.

## Crates

| crate / dir | what it is                                                              |
| ----------- | ----------------------------------------------------------------------- |
| `sin-core`  | keypairs + `npub`/`nsec`, nostr events, challenges, **sessions**, allowlist, verifier |
| `sin-cli`   | `sin` — identities, allowlist, plus `challenge` / `verify`              |
| `sin-middleware` | axum extractors (`Authenticated`, `Session`) + `challenge` / `login` handlers |
| `sin-demo`  | runnable server: serves the PWA *and* SIn-protected endpoints           |
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

## Run the whole thing

The `sin-demo` server hosts the PWA and the protected API on one origin, so you
can do the full passkey → sign → authenticate loop in a browser:

```sh
# 1. Build the PWA the server will serve.
cd web && npm install && npm run build && cd ..

# 2. Start the demo (serves web/dist + /auth/* + /api/*).
SIN_BASE=http://localhost:8080 cargo run -p sin-demo

# 3. Open http://localhost:8080, create an identity (passkey), copy the npub.
# 4. Register it, then restart the server so it reloads the allowlist:
cargo run -p sin-cli -- allow npub1... --label "my phone" --role admin

# 5. Back in the PWA, "Sign in" against http://localhost:8080 — you're in.
```

`SIN_BASE` must equal the origin the browser uses, since NIP-98 tokens bind to
the absolute request URL. The demo wires up both auth styles: `/auth/whoami` is
per-request NIP-98, while `/auth/login` mints a session that authorizes
`/auth/me` and `/api/socket/...`. Other env vars: `SIN_SECRET`,
`SIN_SESSION_SECRET`, `SIN_SESSION_TTL`, `SIN_ALLOWLIST`, `SIN_WEB_DIR`,
`SIN_ADDR`.

## Using it from a server

With `sin-middleware`, protect routes with the `Authenticated` (per-request
NIP-98) or `Session` (cookie/Bearer) extractor, and mount the `challenge` and
`login` handlers:

```rust
use axum::{routing::{get, post}, Json, Router};
use sin_core::{Allowlist, ChallengeKey, SessionKey, Verifier};
use sin_middleware::{challenge, login, Authenticated, Session, SinState};

let state = SinState::new(
    Verifier::new(ChallengeKey::new(challenge_secret, 300), 60),
    Allowlist::load("allowlist.json")?,
    "https://sockets.local",
)
.with_sessions(SessionKey::new(session_secret, 86_400)); // 24h sessions

let app = Router::new()
    .route("/auth/challenge", get(challenge))             // mint a challenge
    .route("/auth/login", post(login))                    // NIP-98 -> session cookie
    .route("/auth/me", get(|Session(s): Session| async move {
        Json(serde_json::json!({ "role": s.role }))       // authorized by the cookie
    }))
    .route("/auth/whoami", get(|Authenticated(s): Authenticated| async move {
        Json(serde_json::json!({ "role": s.role }))       // per-request NIP-98
    }))
    .with_state(state);
```

Or drive `sin-core` directly, without the axum layer:

```rust
use sin_core::{Allowlist, ChallengeKey, SessionKey, Verifier};

let allowlist = Allowlist::load("allowlist.json")?;
let verifier = Verifier::new(ChallengeKey::new(server_secret_bytes, 300), 60);
let sessions = SessionKey::new(session_secret_bytes, 86_400);

let challenge_str = verifier.issue_challenge(now_unix);          // GET /auth/challenge
let signin = verifier.verify(&auth_header, "POST", &url, &allowlist, now_unix)?;
let token = sessions.issue(&signin.pubkey, &signin.role, &signin.label, now_unix);
// ... later, on a session-protected route:
let session = sessions.verify(&token, now_unix)?;
println!("authenticated {} as {}", session.label, session.role);
```

## Status / roadmap

- [x] `sin-core`: keys, NIP-19, NIP-98 verification, stateless challenges, replay
      cache, allowlist
- [x] `sin-cli`: identity + allowlist management, plus `challenge` / `verify`
- [x] **signer PWA** (`web/`): on-device keypair, passkey-gated via WebAuthn PRF,
      NIP-98 signing, installable/offline, JS↔Rust interop-tested
- [x] `sin-middleware`: axum `Authenticated` + `Session` extractors, `challenge`
      + `login` handlers
- [x] **session issuance**: stateless HMAC session token (cookie or Bearer) after
      a successful sign-in — sign once, then act (live-tested)
- [x] `sin-demo`: runnable server hosting the PWA + protected routes (live-tested)
- [ ] `examples/rf-socket`: wired into rf-socket-controller

## Security notes

- The in-browser key is encrypted at rest (AES-256-GCM) and unlocked with a
  passkey (WebAuthn PRF) — passwordless but theft-resistant.
- The replay cache is process-local; for multi-instance deployments back it with
  a shared store.
- Losing a device means losing that identity — by design. Re-enrolling is one
  `sin allow` away.

## License

MIT
