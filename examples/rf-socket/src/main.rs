//! Example: an RF socket controller fronted by SIn.
//!
//! This is the shape a real `rf-socket-controller` would take. It shows the
//! three things an app actually needs on top of `sin-core`:
//!
//! 1. **Session auth** — sign in once with a passkey-held key (`POST /auth/login`),
//!    then drive the device with the session cookie.
//! 2. **Role-based authorization** — everyone listed may *toggle* a socket, but
//!    only an `admin` may *add or remove* sockets. The role rides in the signed
//!    session, so the check is a cheap string compare with no extra lookup.
//! 3. **Domain state** — an in-memory bank of RF sockets standing in for the
//!    real radio. Swap [`actuate`] for your 433 MHz transmitter and you're done.
//!
//! Combined app state ([`App`]) bundles the controller's socket bank with SIn's
//! [`SinState`]; `FromRef` lets the SIn extractors pull what they need.
//!
//! Run it:
//! ```sh
//! SIN_BASE=http://localhost:8090 SIN_ADDR=127.0.0.1:8090 \
//!   cargo run -p rf-socket
//! ```
//! then register an npub with `sin allow ... --role admin` (or `--role user`).

use std::collections::BTreeMap;
use std::env;
use std::sync::{Arc, Mutex};

use axum::extract::{FromRef, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde_json::json;
use tower_http::services::ServeDir;

use sin_core::{Allowlist, ChallengeKey, SessionKey, Verifier};
use sin_middleware::{challenge, login, Session, SinState};

/// One controllable RF socket.
#[derive(Clone)]
struct Socket {
    name: String,
    on: bool,
}

/// The controller's domain state: a bank of sockets behind a mutex.
#[derive(Clone, Default)]
struct Sockets(Arc<Mutex<BTreeMap<String, Socket>>>);

/// Combined application state. The SIn extractors reach `SinState` via the
/// [`FromRef`] impl below; our handlers reach the socket bank the same way.
#[derive(Clone)]
struct App {
    sin: SinState,
    sockets: Sockets,
}

impl FromRef<App> for SinState {
    fn from_ref(app: &App) -> SinState {
        app.sin.clone()
    }
}

impl FromRef<App> for Sockets {
    fn from_ref(app: &App) -> Sockets {
        app.sockets.clone()
    }
}

#[tokio::main]
async fn main() {
    let base = env::var("SIN_BASE").unwrap_or_else(|_| "http://localhost:8090".to_string());
    let allowlist_path = env::var("SIN_ALLOWLIST").unwrap_or_else(|_| "allowlist.json".to_string());
    let web_dir = env::var("SIN_WEB_DIR").unwrap_or_else(|_| "web/dist".to_string());
    let addr = env::var("SIN_ADDR").unwrap_or_else(|_| "0.0.0.0:8090".to_string());

    let secret = match env::var("SIN_SECRET") {
        Ok(hex) => hex::decode(hex.trim()).expect("SIN_SECRET must be hex"),
        Err(_) => {
            let mut s = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut s);
            eprintln!("SIN_SECRET not set; using a random ephemeral secret: {}", hex::encode(s));
            s.to_vec()
        }
    };
    let session_secret = match env::var("SIN_SESSION_SECRET") {
        Ok(hex) => hex::decode(hex.trim()).expect("SIN_SESSION_SECRET must be hex"),
        Err(_) => derive_session_secret(&secret),
    };

    let allowlist = Allowlist::load(&allowlist_path).expect("failed to read allowlist");
    if allowlist.is_empty() {
        eprintln!("warning: {allowlist_path} is empty — enroll, then `sin allow <npub> --role admin`");
    }

    let sin = SinState::new(Verifier::new(ChallengeKey::new(secret, 300), 60), allowlist, &base)
        .with_sessions(SessionKey::new(session_secret, 86_400));

    // Seed a couple of sockets so the controller has something to show.
    let sockets = Sockets::default();
    {
        let mut bank = sockets.0.lock().unwrap();
        bank.insert("1".into(), Socket { name: "desk lamp".into(), on: false });
        bank.insert("2".into(), Socket { name: "heater".into(), on: false });
    }

    let app = App { sin, sockets };

    let router = Router::new()
        .route("/auth/challenge", get(challenge))
        .route("/auth/login", post(login))
        .route("/auth/me", get(me))
        .route("/api/sockets", get(list).post(add))
        .route("/api/sockets/{id}/{action}", post(actuate))
        .route("/api/sockets/{id}", axum::routing::delete(remove))
        .fallback_service(ServeDir::new(&web_dir))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind failed");
    eprintln!("rf-socket controller on http://{addr}  (external base: {base})");
    axum::serve(listener, router).await.expect("server error");
}

// ---- handlers -------------------------------------------------------------

/// Session-authorized identity echo (any registered key).
async fn me(Session(s): Session) -> Json<serde_json::Value> {
    Json(json!({ "npub": s.pubkey.to_npub(), "role": s.role, "label": s.label }))
}

/// List all sockets and their state. Any authenticated session may read.
async fn list(Session(_s): Session, State(sockets): State<Sockets>) -> Json<serde_json::Value> {
    let bank = sockets.0.lock().unwrap();
    let items: Vec<_> = bank
        .iter()
        .map(|(id, s)| json!({ "id": id, "name": s.name, "on": s.on }))
        .collect();
    Json(json!({ "sockets": items }))
}

/// Turn a socket `on`, `off`, or `toggle` it. Any registered user may actuate.
async fn actuate(
    Session(s): Session,
    State(sockets): State<Sockets>,
    Path((id, action)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut bank = sockets.0.lock().unwrap();
    let socket = bank.get_mut(&id).ok_or(ApiError::NotFound)?;
    socket.on = match action.as_str() {
        "on" => true,
        "off" => false,
        "toggle" => !socket.on,
        _ => return Err(ApiError::BadAction),
    };
    // A real controller drives the 433 MHz transmitter here.
    actuate_radio(&id, socket.on);
    Ok(Json(json!({
        "id": id,
        "name": socket.name,
        "on": socket.on,
        "by": s.pubkey.to_npub(),
    })))
}

#[derive(serde::Deserialize)]
struct NewSocket {
    id: String,
    name: String,
}

/// Register a new socket. **Admin only.**
async fn add(
    Session(s): Session,
    State(sockets): State<Sockets>,
    Json(req): Json<NewSocket>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&s.role)?;
    let mut bank = sockets.0.lock().unwrap();
    bank.insert(req.id.clone(), Socket { name: req.name.clone(), on: false });
    Ok(Json(json!({ "added": req.id, "name": req.name })))
}

/// Remove a socket. **Admin only.**
async fn remove(
    Session(s): Session,
    State(sockets): State<Sockets>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_admin(&s.role)?;
    let removed = sockets.0.lock().unwrap().remove(&id).is_some();
    if removed {
        Ok(Json(json!({ "removed": id })))
    } else {
        Err(ApiError::NotFound)
    }
}

// ---- authorization + errors ----------------------------------------------

fn require_admin(role: &str) -> Result<(), ApiError> {
    if role == "admin" {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Application-level errors, rendered as JSON with a fitting status.
enum ApiError {
    NotFound,
    BadAction,
    Forbidden,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "no such socket"),
            ApiError::BadAction => (StatusCode::BAD_REQUEST, "action must be on, off, or toggle"),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "admin role required"),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

// ---- glue -----------------------------------------------------------------

/// Stand-in for the radio. Replace with your 433 MHz transmit code.
fn actuate_radio(id: &str, on: bool) {
    eprintln!("[rf] socket {id} -> {}", if on { "ON" } else { "OFF" });
}

/// Domain-separated derivation so one `SIN_SECRET` yields a distinct session key.
fn derive_session_secret(challenge_secret: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(challenge_secret).expect("any key length");
    mac.update(b"sin-session-secret-v1");
    mac.finalize().into_bytes().to_vec()
}
