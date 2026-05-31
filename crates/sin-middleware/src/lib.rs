//! axum integration for SIn.
//!
//! Provides three things:
//! * [`SinState`] — shared verifier + allowlist + the server's external base URL.
//! * [`challenge`] — a handler for `GET /auth/challenge`.
//! * [`Authenticated`] — an extractor that verifies the NIP-98 `Authorization`
//!   header and yields the [`SignIn`] for the request.
//!
//! ```no_run
//! use std::sync::Arc;
//! use axum::{routing::get, Json, Router};
//! use sin_core::{Allowlist, ChallengeKey, Verifier};
//! use sin_middleware::{challenge, Authenticated, SinState};
//!
//! async fn whoami(Authenticated(s): Authenticated) -> Json<serde_json::Value> {
//!     Json(serde_json::json!({ "npub": s.pubkey.to_npub(), "role": s.role }))
//! }
//!
//! let state = SinState::new(
//!     Verifier::new(ChallengeKey::new(*b"32-byte-per-deployment-secret!!!", 300), 60),
//!     Allowlist::load("allowlist.json").unwrap(),
//!     "https://sockets.local",
//! );
//! let app: Router = Router::new()
//!     .route("/auth/challenge", get(challenge))
//!     .route("/auth/whoami", get(whoami))
//!     .with_state(state);
//! ```

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use sin_core::{Allowlist, Error, SignIn, Verifier};

/// Shared application state for SIn-protected routes.
///
/// Cheap to clone (everything is behind `Arc`). Add it to your router with
/// `.with_state(state)`, or embed it in a larger state via [`FromRef`].
#[derive(Clone)]
pub struct SinState {
    verifier: Arc<Verifier>,
    allowlist: Arc<Allowlist>,
    /// The server's externally-visible base URL, e.g. `https://sockets.local`.
    /// NIP-98 tokens bind to an absolute URL, so we rebuild it as
    /// `external_base + request path` to compare against what the client signed.
    external_base: Arc<str>,
}

impl SinState {
    pub fn new(verifier: Verifier, allowlist: Allowlist, external_base: impl Into<String>) -> Self {
        let base = external_base.into();
        Self {
            verifier: Arc::new(verifier),
            allowlist: Arc::new(allowlist),
            external_base: Arc::from(base.trim_end_matches('/')),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the unix epoch")
        .as_secs()
}

/// `GET /auth/challenge` — mint a fresh challenge for the client to sign.
pub async fn challenge(State(state): State<SinState>) -> Json<serde_json::Value> {
    Json(json!({ "challenge": state.verifier.issue_challenge(now_unix()) }))
}

/// Extractor that authenticates a request via its NIP-98 `Authorization` header.
///
/// On success yields the verified [`SignIn`]; on failure short-circuits with a
/// `401` (or `403` for a valid-but-unlisted key).
pub struct Authenticated(pub SignIn);

impl<S> FromRequestParts<S> for Authenticated
where
    S: Send + Sync,
    SinState: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = SinState::from_ref(state);

        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthError(Error::Unauthorized("missing Authorization header".into())))?;

        let path = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(parts.uri.path());
        let url = format!("{}{}", state.external_base, path);
        let method = parts.method.as_str();

        state
            .verifier
            .verify(header, method, &url, &state.allowlist, now_unix())
            .map(Authenticated)
            .map_err(AuthError)
    }
}

/// Rejection type for [`Authenticated`]. Renders as a JSON error with an
/// appropriate status code.
pub struct AuthError(pub Error);

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            Error::NotAllowed => StatusCode::FORBIDDEN,
            _ => StatusCode::UNAUTHORIZED,
        };
        (status, Json(json!({ "error": self.0.to_string() }))).into_response()
    }
}
