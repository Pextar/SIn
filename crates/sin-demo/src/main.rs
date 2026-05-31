//! A runnable demo of the whole SIn loop on a single origin.
//!
//! It serves the signer PWA (`web/dist`) *and* SIn-protected API endpoints, so
//! you can install the PWA, unlock with a passkey, and sign in — no CORS, stable
//! passkey origin. This is the shape `rf-socket-controller` would take.
//!
//! Configure via environment variables:
//!   SIN_SECRET     hex challenge secret (default: random, printed at startup)
//!   SIN_BASE       external base URL the browser uses (default http://localhost:8080)
//!   SIN_ALLOWLIST  path to allowlist.json (default ./allowlist.json)
//!   SIN_WEB_DIR    path to the built PWA (default ./web/dist)
//!   SIN_ADDR       listen address (default 0.0.0.0:8080)

use std::env;

use axum::extract::Path;
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde_json::json;
use tower_http::services::ServeDir;

use sin_core::{Allowlist, ChallengeKey, Verifier};
use sin_middleware::{challenge, Authenticated, SinState};

#[tokio::main]
async fn main() {
    let base = env::var("SIN_BASE").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let allowlist_path = env::var("SIN_ALLOWLIST").unwrap_or_else(|_| "allowlist.json".to_string());
    let web_dir = env::var("SIN_WEB_DIR").unwrap_or_else(|_| "web/dist".to_string());
    let addr = env::var("SIN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let secret = match env::var("SIN_SECRET") {
        Ok(hex) => hex::decode(hex.trim()).expect("SIN_SECRET must be hex"),
        Err(_) => {
            let mut s = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut s);
            eprintln!("SIN_SECRET not set; using a random ephemeral secret: {}", hex::encode(s));
            s.to_vec()
        }
    };

    let allowlist = Allowlist::load(&allowlist_path).expect("failed to read allowlist");
    if allowlist.is_empty() {
        eprintln!("warning: {allowlist_path} is empty — enroll in the PWA, then `sin allow <npub>`");
    }

    let verifier = Verifier::new(ChallengeKey::new(secret, 300), 60);
    let state = SinState::new(verifier, allowlist, &base);

    let app = Router::new()
        .route("/auth/challenge", get(challenge))
        .route("/auth/whoami", get(whoami))
        .route("/api/socket/{id}/{action}", post(socket))
        .fallback_service(ServeDir::new(&web_dir))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind failed");
    eprintln!("SIn demo on http://{addr}  (external base: {base}, PWA: {web_dir})");
    axum::serve(listener, app).await.expect("server error");
}

/// Protected: report who you are.
async fn whoami(Authenticated(s): Authenticated) -> Json<serde_json::Value> {
    Json(json!({ "npub": s.pubkey.to_npub(), "role": s.role, "label": s.label }))
}

/// Protected demo endpoint standing in for an RF socket toggle.
async fn socket(
    Authenticated(s): Authenticated,
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
