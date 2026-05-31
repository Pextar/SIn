//! axum integration for SIn.
//!
//! Two ways to authenticate a request:
//!
//! * [`Authenticated`] — verifies a per-request NIP-98 `Authorization` header
//!   and yields a [`SignIn`]. Great for CLIs; the client signs every call.
//! * [`Session`] — verifies a session token (cookie or `Bearer`) minted by
//!   [`login`] after one NIP-98 sign-in. Great for browsers: sign once, then
//!   make many calls.
//!
//! Endpoints provided as handlers: [`challenge`] (`GET /auth/challenge`) and
//! [`login`] (`POST /auth/login`).
//!
//! ```no_run
//! use axum::{routing::{get, post}, Json, Router};
//! use sin_core::{Allowlist, ChallengeKey, SessionKey, Verifier};
//! use sin_middleware::{challenge, login, Session, SinState};
//!
//! async fn whoami(Session(s): Session) -> Json<serde_json::Value> {
//!     Json(serde_json::json!({ "npub": s.pubkey.to_npub(), "role": s.role }))
//! }
//!
//! let state = SinState::new(
//!     Verifier::new(ChallengeKey::new(*b"32-byte-per-deployment-secret!!!", 300), 60),
//!     Allowlist::load("allowlist.json").unwrap(),
//!     "https://sockets.local",
//! )
//! .with_sessions(SessionKey::new(*b"a-distinct-32-byte-session-key!!", 86_400));
//!
//! let app: Router = Router::new()
//!     .route("/auth/challenge", get(challenge))
//!     .route("/auth/login", post(login))
//!     .route("/auth/whoami", get(whoami))
//!     .with_state(state);
//! ```

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use sin_core::{Allowlist, Error, Session as CoreSession, SessionKey, SignIn, Verifier};

/// Name of the cookie that carries the session token.
pub const SESSION_COOKIE: &str = "sin_session";

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
    /// Optional session signer. Present once [`SinState::with_sessions`] is
    /// called; [`login`] and the [`Session`] extractor require it.
    sessions: Option<Arc<SessionKey>>,
    /// Whether to mark the session cookie `Secure` (true for https origins).
    secure_cookie: bool,
}

impl SinState {
    pub fn new(verifier: Verifier, allowlist: Allowlist, external_base: impl Into<String>) -> Self {
        let base = external_base.into();
        let secure_cookie = base.starts_with("https://");
        Self {
            verifier: Arc::new(verifier),
            allowlist: Arc::new(allowlist),
            external_base: Arc::from(base.trim_end_matches('/')),
            sessions: None,
            secure_cookie,
        }
    }

    /// Enable session issuance with the given signer. Without this, [`login`]
    /// and the [`Session`] extractor return `501 Not Implemented`.
    pub fn with_sessions(mut self, key: SessionKey) -> Self {
        self.sessions = Some(Arc::new(key));
        self
    }

    fn session_key(&self) -> Result<&SessionKey, AuthError> {
        self.sessions
            .as_deref()
            .ok_or(AuthError(AuthFailure::SessionsDisabled))
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

/// `POST /auth/login` — exchange a one-shot NIP-98 sign-in for a session.
///
/// The request must carry a valid NIP-98 `Authorization` header bound to this
/// endpoint (exactly like any [`Authenticated`] route). On success the response
/// sets an `HttpOnly` session cookie *and* returns the token in the body, so
/// both browser and programmatic clients are covered.
pub async fn login(
    State(state): State<SinState>,
    Authenticated(signin): Authenticated,
) -> Result<Response, AuthError> {
    let key = state.session_key()?;
    let now = now_unix();
    let token = key.issue(&signin.pubkey, &signin.role, &signin.label, now);

    let cookie = format!(
        "{name}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={age}{secure}",
        name = SESSION_COOKIE,
        age = key.ttl_secs(),
        secure = if state.secure_cookie { "; Secure" } else { "" },
    );

    let body = Json(json!({
        "token": token,
        "npub": signin.pubkey.to_npub(),
        "role": signin.role,
        "label": signin.label,
        "expires_at": now + key.ttl_secs(),
    }));

    let mut response = body.into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        cookie.parse().expect("session cookie is a valid header value"),
    );
    Ok(response)
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
            .ok_or(AuthError(AuthFailure::Sin(Error::Unauthorized(
                "missing Authorization header".into(),
            ))))?;

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
            .map_err(|e| AuthError(AuthFailure::Sin(e)))
    }
}

/// Extractor that authenticates a request via its SIn session token.
///
/// The token is read from the `sin_session` cookie or, failing that, an
/// `Authorization: Bearer <token>` header. On success yields the [`CoreSession`];
/// on failure short-circuits with `401` (or `501` if sessions aren't enabled).
pub struct Session(pub CoreSession);

impl<S> FromRequestParts<S> for Session
where
    S: Send + Sync,
    SinState: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = SinState::from_ref(state);
        let key = state.session_key()?;

        let token = session_token_from(parts).ok_or(AuthError(AuthFailure::Sin(
            Error::Session("missing session token".into()),
        )))?;

        key.verify(&token, now_unix())
            .map(Session)
            .map_err(|e| AuthError(AuthFailure::Sin(e)))
    }
}

/// Pull a session token out of the request: cookie first, then `Bearer` header.
fn session_token_from(parts: &Parts) -> Option<String> {
    if let Some(cookies) = parts.headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        if let Some(tok) = cookie_value(cookies, SESSION_COOKIE) {
            return Some(tok.to_string());
        }
    }
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string())
}

/// Find `name`'s value in a `Cookie` header (`a=1; b=2`).
fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

/// Why authentication failed, mapped to a status code by [`IntoResponse`].
enum AuthFailure {
    /// A SIn-core error (bad signature, expired challenge/session, not allowed).
    Sin(Error),
    /// A session route was hit but session issuance isn't configured.
    SessionsDisabled,
}

/// Rejection type for the extractors and [`login`]. Renders as a JSON error
/// with an appropriate status code.
pub struct AuthError(AuthFailure);

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self.0 {
            AuthFailure::Sin(Error::NotAllowed) => {
                (StatusCode::FORBIDDEN, Error::NotAllowed.to_string())
            }
            AuthFailure::Sin(e) => (StatusCode::UNAUTHORIZED, e.to_string()),
            AuthFailure::SessionsDisabled => (
                StatusCode::NOT_IMPLEMENTED,
                "session issuance is not configured".to_string(),
            ),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
