//! A runnable demo of the whole SIn loop on a single origin.
//!
//! It serves the signer PWA (`web/dist`) *and* SIn-protected API endpoints, so
//! you can install the PWA, unlock with a passkey, and sign in — no CORS, stable
//! passkey origin. This is the shape `rf-socket-controller` would take.
//!
//! Two auth styles are demonstrated:
//!   * `/auth/whoami`            — per-request NIP-98 (sign every call).
//!   * `POST /auth/login`        — exchange one NIP-98 sign-in for a session cookie.
//!   * `/api/socket/{id}/{act}`  — protected by that session (sign once, act many).
//!
//! Configure via environment variables:
//!   SIN_SECRET          hex challenge secret (default: random, printed at startup)
//!   SIN_SESSION_SECRET  hex session secret (default: derived from SIN_SECRET)
//!   SIN_SESSION_TTL     session lifetime in seconds (default 86400)
//!   SIN_BASE            external base URL the browser uses (default http://localhost:8080)
//!   SIN_ALLOWLIST       path to allowlist.json (default ./allowlist.json)
//!   SIN_WEB_DIR         path to the built PWA (default ./web/dist)
//!   SIN_ADDR            listen address (default 0.0.0.0:8080)

use std::env;

use axum::extract::Path;
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde_json::json;
use tower_http::services::ServeDir;

use sin_core::{Allowlist, ChallengeKey, SessionKey, Verifier};
use sin_middleware::{challenge, login, Authenticated, Session, SinState};

#[tokio::main]
async fn main() {
    let base = env::var("SIN_BASE").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let allowlist_path = env::var("SIN_ALLOWLIST").unwrap_or_else(|_| "allowlist.json".to_string());
    let web_dir = env::var("SIN_WEB_DIR").unwrap_or_else(|_| "web/dist".to_string());
    let addr = env::var("SIN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let session_ttl: u64 = env::var("SIN_SESSION_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(86_400);

    let secret = match env::var("SIN_SECRET") {
        Ok(hex) => hex::decode(hex.trim()).expect("SIN_SECRET must be hex"),
        Err(_) => {
            let mut s = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut s);
            eprintln!("SIN_SECRET not set; using a random ephemeral secret: {}", hex::encode(s));
            s.to_vec()
        }
    };

    // A *distinct* secret for session tokens. Derived from SIN_SECRET by default
    // (domain-separated) so a single configured secret still yields two keys.
    let session_secret = match env::var("SIN_SESSION_SECRET") {
        Ok(hex) => hex::decode(hex.trim()).expect("SIN_SESSION_SECRET must be hex"),
        Err(_) => derive_session_secret(&secret),
    };

    let allowlist = Allowlist::load(&allowlist_path).expect("failed to read allowlist");
    if allowlist.is_empty() {
        eprintln!("warning: {allowlist_path} is empty — enroll in the PWA, then `sin allow <npub>`");
    }

    let verifier = Verifier::new(ChallengeKey::new(secret, 300), 60);
    let state = SinState::new(verifier, allowlist, &base)
        .with_sessions(SessionKey::new(session_secret, session_ttl));

    let app = Router::new()
        .route("/auth/challenge", get(challenge))
        .route("/auth/login", post(login))
        .route("/auth/whoami", get(whoami))
        .route("/auth/me", get(me))
        .route("/api/socket/{id}/{action}", post(socket))
        .fallback_service(ServeDir::new(&web_dir))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind failed");
    eprintln!("SIn demo on http://{addr}  (external base: {base}, PWA: {web_dir})");
    axum::serve(listener, app).await.expect("server error");
}

/// Domain-separated derivation so one `SIN_SECRET` yields a distinct session key.
fn derive_session_secret(challenge_secret: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(challenge_secret).expect("any key length");
    mac.update(b"sin-session-secret-v1");
    mac.finalize().into_bytes().to_vec()
}

/// Protected by per-request NIP-98: report who you are.
async fn whoami(Authenticated(s): Authenticated) -> Json<serde_json::Value> {
    Json(json!({ "npub": s.pubkey.to_npub(), "role": s.role, "label": s.label }))
}

/// Protected by a session: the same identity info, but authorized by the
/// session cookie rather than a fresh signature. Handy for "am I still signed
/// in?" checks from the PWA.
async fn me(Session(s): Session) -> Json<serde_json::Value> {
    Json(json!({
        "npub": s.pubkey.to_npub(),
        "role": s.role,
        "label": s.label,
        "expires_at": s.expires_at,
    }))
}

/// Protected by a session token (cookie or Bearer): stand-in for an RF socket
/// toggle. The client signs in once via `/auth/login`, then calls this freely.
async fn socket(
    Session(s): Session,
    Path((id, action)): Path<(String, String)>,
) -> Json<serde_json::Value> {
    // A real controller would actuate the socket here.
    Json(json!({
        "ok": true,
        "socket": id,
        "action": action,
        "by": s.pubkey.to_npub(),
    }))
}
