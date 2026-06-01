//! Example: a passwordless **home hub** fronted by SIn.
//!
//! This grew out of a single RF-socket controller into the shape a real home
//! hub takes. It shows the four things such an app needs on top of `sin-core`:
//!
//! 1. **Session auth** — sign in once with a passkey-held key (`POST /auth/login`),
//!    then drive the hub with the session cookie.
//! 2. **Role-based authorization** — anyone listed may *read* and *actuate*
//!    devices and *apply* scenes, but only an `admin` may *add or remove* devices
//!    and scenes. The role rides in the signed session, so the check is a cheap
//!    string compare with no extra lookup.
//! 3. **A real device model** — not one hardcoded gadget but a [`Device`] with
//!    several *kinds*: a [`Switch`](Device::Switch) (an RF socket), a
//!    [`Dimmer`](Device::Dimmer) (a light with a 0–100 level), and a read-only
//!    [`Sensor`](Device::Sensor). Adding a new gadget is a data change, not a new
//!    endpoint. Swap [`actuate_radio`] for your 433 MHz transmitter and it's real.
//! 4. **Scenes** — a named set of commands applied together ("movie night"),
//!    layered above individual devices.
//!
//! Combined app state ([`App`]) bundles the hub with SIn's [`SinState`];
//! `FromRef` lets the SIn extractors pull what they need.
//!
//! Run it:
//! ```sh
//! SIN_BASE=http://localhost:8090 SIN_ADDR=127.0.0.1:8090 \
//!   cargo run -p home-hub
//! ```
//! then register an npub with `sin allow ... --role admin` (or `--role user`).

use std::collections::BTreeMap;
use std::env;
use std::sync::{Arc, Mutex};

use axum::extract::{FromRef, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_http::services::ServeDir;

use sin_core::{Allowlist, ChallengeKey, SessionKey, Verifier};
use sin_middleware::{challenge, login, Session, SinState};

// ---- device model ---------------------------------------------------------

/// One controllable (or observable) thing the hub knows about.
///
/// The `kind` tag is what turns "socket controller" into "home hub": each
/// variant carries its own state and accepts its own commands.
#[derive(Clone)]
enum Device {
    /// A plain on/off device — an RF socket.
    Switch { name: String, on: bool },
    /// A dimmable light: on/off plus a brightness `level` in `0..=100`.
    Dimmer { name: String, on: bool, level: u8 },
    /// A read-only sensor the hub reports but you don't actuate.
    Sensor { name: String, reading: Reading },
}

/// A sensor reading. Read-only: the hub surfaces it, commands never touch it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Reading {
    Temperature { celsius: f64 },
    Humidity { percent: f64 },
    /// A contact sensor — `closed` is true for a shut door/window.
    Contact { closed: bool },
}

/// A command aimed at a device. Reused by both the per-device endpoint and by
/// scene steps, so "set the light to 20%" means the same thing everywhere.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Command {
    On,
    Off,
    Toggle,
    /// Set a dimmer's brightness (`0..=100`); 0 also turns it off.
    Level { value: u8 },
}

impl Device {
    /// Can this device accept `cmd`? Pure check, no mutation — lets a scene
    /// validate every step before changing anything (all-or-nothing apply).
    fn accepts(&self, cmd: &Command) -> Result<(), ApiError> {
        match (self, cmd) {
            (Device::Sensor { .. }, _) => Err(ApiError::ReadOnly),
            (Device::Switch { .. }, Command::Level { .. }) => Err(ApiError::Unsupported),
            (_, Command::Level { value }) if *value > 100 => Err(ApiError::BadLevel),
            _ => Ok(()),
        }
    }

    /// Apply `cmd`, mutating the device's state. Validates via [`accepts`] first.
    fn apply(&mut self, cmd: &Command) -> Result<(), ApiError> {
        self.accepts(cmd)?;
        match self {
            Device::Switch { on, .. } => match cmd {
                Command::On => *on = true,
                Command::Off => *on = false,
                Command::Toggle => *on = !*on,
                Command::Level { .. } => unreachable!("rejected by accepts"),
            },
            Device::Dimmer { on, level, .. } => match cmd {
                Command::On => *on = true,
                Command::Off => *on = false,
                Command::Toggle => *on = !*on,
                Command::Level { value } => {
                    *level = *value;
                    *on = *value > 0;
                }
            },
            Device::Sensor { .. } => unreachable!("rejected by accepts"),
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        match self {
            Device::Switch { .. } => "switch",
            Device::Dimmer { .. } => "dimmer",
            Device::Sensor { .. } => "sensor",
        }
    }

    /// A short human/radio-log summary of current state.
    fn summary(&self) -> String {
        match self {
            Device::Switch { on, .. } => if *on { "ON" } else { "OFF" }.to_string(),
            Device::Dimmer { on, level, .. } => {
                if *on {
                    format!("ON @ {level}%")
                } else {
                    "OFF".to_string()
                }
            }
            Device::Sensor { reading, .. } => format!("{reading:?} (read-only)"),
        }
    }

    fn to_json(&self, id: &str) -> Value {
        match self {
            Device::Switch { name, on } => {
                json!({ "id": id, "kind": "switch", "name": name, "on": on })
            }
            Device::Dimmer { name, on, level } => {
                json!({ "id": id, "kind": "dimmer", "name": name, "on": on, "level": level })
            }
            Device::Sensor { name, reading } => {
                json!({ "id": id, "kind": "sensor", "name": name, "reading": reading })
            }
        }
    }
}

// Debug is only used by `summary` for sensors; keep it terse.
impl std::fmt::Debug for Reading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reading::Temperature { celsius } => write!(f, "{celsius}°C"),
            Reading::Humidity { percent } => write!(f, "{percent}%RH"),
            Reading::Contact { closed } => write!(f, "{}", if *closed { "closed" } else { "open" }),
        }
    }
}

/// A named bundle of commands applied together.
#[derive(Clone)]
struct Scene {
    name: String,
    steps: Vec<SceneStep>,
}

/// One step of a scene: aim a [`Command`] at a device.
#[derive(Clone, Serialize, Deserialize)]
struct SceneStep {
    device: String,
    command: Command,
}

// ---- app state ------------------------------------------------------------

/// The hub's domain state: devices and scenes behind one mutex.
#[derive(Default)]
struct HubState {
    devices: BTreeMap<String, Device>,
    scenes: BTreeMap<String, Scene>,
}

#[derive(Clone, Default)]
struct Hub(Arc<Mutex<HubState>>);

/// Combined application state. The SIn extractors reach `SinState` via the
/// [`FromRef`] impl below; our handlers reach the hub the same way.
#[derive(Clone)]
struct App {
    sin: SinState,
    hub: Hub,
}

impl FromRef<App> for SinState {
    fn from_ref(app: &App) -> SinState {
        app.sin.clone()
    }
}

impl FromRef<App> for Hub {
    fn from_ref(app: &App) -> Hub {
        app.hub.clone()
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

    let app = App { sin, hub: seed_hub() };

    let router = Router::new()
        .route("/auth/challenge", get(challenge))
        .route("/auth/login", post(login))
        .route("/auth/me", get(me))
        .route("/api/devices", get(list_devices).post(add_device))
        .route("/api/devices/{id}", post(command_device).delete(remove_device))
        .route("/api/scenes", get(list_scenes).post(add_scene))
        .route("/api/scenes/{id}", delete(remove_scene))
        .route("/api/scenes/{id}/apply", post(apply_scene))
        .fallback_service(ServeDir::new(&web_dir))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind failed");
    eprintln!("home hub on http://{addr}  (external base: {base})");
    axum::serve(listener, router).await.expect("server error");
}

/// Seed a few devices and a scene so the hub has something to show.
fn seed_hub() -> Hub {
    let hub = Hub::default();
    {
        let mut st = hub.0.lock().unwrap();
        st.devices.insert("lamp".into(), Device::Switch { name: "desk lamp".into(), on: false });
        st.devices.insert("heater".into(), Device::Switch { name: "space heater".into(), on: false });
        st.devices.insert(
            "ceiling".into(),
            Device::Dimmer { name: "ceiling light".into(), on: false, level: 0 },
        );
        st.devices.insert(
            "temp".into(),
            Device::Sensor { name: "living room".into(), reading: Reading::Temperature { celsius: 21.5 } },
        );
        st.devices.insert(
            "door".into(),
            Device::Sensor { name: "front door".into(), reading: Reading::Contact { closed: true } },
        );
        st.scenes.insert(
            "movie".into(),
            Scene {
                name: "movie night".into(),
                steps: vec![
                    SceneStep { device: "lamp".into(), command: Command::Off },
                    SceneStep { device: "heater".into(), command: Command::On },
                    SceneStep { device: "ceiling".into(), command: Command::Level { value: 20 } },
                ],
            },
        );
    }
    hub
}

// ---- device handlers ------------------------------------------------------

/// Session-authorized identity echo (any registered key).
async fn me(Session(s): Session) -> Json<Value> {
    Json(json!({ "npub": s.pubkey.to_npub(), "role": s.role, "label": s.label }))
}

/// List every device and its state. Any authenticated session may read.
async fn list_devices(Session(_s): Session, State(hub): State<Hub>) -> Json<Value> {
    let st = hub.0.lock().unwrap();
    let items: Vec<_> = st.devices.iter().map(|(id, d)| d.to_json(id)).collect();
    Json(json!({ "devices": items }))
}

/// Send a command to a device. Any registered user may actuate.
async fn command_device(
    Session(s): Session,
    State(hub): State<Hub>,
    Path(id): Path<String>,
    Json(cmd): Json<Command>,
) -> Result<Json<Value>, ApiError> {
    let mut st = hub.0.lock().unwrap();
    let dev = st.devices.get_mut(&id).ok_or(ApiError::NotFound)?;
    dev.apply(&cmd)?;
    actuate_radio(&id, dev);
    let mut out = dev.to_json(&id);
    out["by"] = json!(s.pubkey.to_npub());
    Ok(Json(out))
}

/// How a device is specified when added. The `kind` tag selects the variant.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum NewDevice {
    Switch { id: String, name: String },
    Dimmer { id: String, name: String },
    Sensor { id: String, name: String, reading: Reading },
}

impl NewDevice {
    fn into_device(self) -> (String, Device) {
        match self {
            NewDevice::Switch { id, name } => (id, Device::Switch { name, on: false }),
            NewDevice::Dimmer { id, name } => (id, Device::Dimmer { name, on: false, level: 0 }),
            NewDevice::Sensor { id, name, reading } => (id, Device::Sensor { name, reading }),
        }
    }
}

/// Register a new device. **Admin only.**
async fn add_device(
    Session(s): Session,
    State(hub): State<Hub>,
    Json(req): Json<NewDevice>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&s.role)?;
    let (id, dev) = req.into_device();
    let kind = dev.kind();
    hub.0.lock().unwrap().devices.insert(id.clone(), dev);
    Ok(Json(json!({ "added": id, "kind": kind })))
}

/// Remove a device. **Admin only.**
async fn remove_device(
    Session(s): Session,
    State(hub): State<Hub>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&s.role)?;
    let removed = hub.0.lock().unwrap().devices.remove(&id).is_some();
    if removed {
        Ok(Json(json!({ "removed": id })))
    } else {
        Err(ApiError::NotFound)
    }
}

// ---- scene handlers -------------------------------------------------------

/// List every scene. Any authenticated session may read.
async fn list_scenes(Session(_s): Session, State(hub): State<Hub>) -> Json<Value> {
    let st = hub.0.lock().unwrap();
    let items: Vec<_> = st
        .scenes
        .iter()
        .map(|(id, sc)| json!({ "id": id, "name": sc.name, "steps": sc.steps }))
        .collect();
    Json(json!({ "scenes": items }))
}

#[derive(Deserialize)]
struct NewScene {
    id: String,
    name: String,
    steps: Vec<SceneStep>,
}

/// Create a scene. **Admin only.**
async fn add_scene(
    Session(s): Session,
    State(hub): State<Hub>,
    Json(req): Json<NewScene>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&s.role)?;
    let id = req.id.clone();
    hub.0
        .lock()
        .unwrap()
        .scenes
        .insert(id.clone(), Scene { name: req.name, steps: req.steps });
    Ok(Json(json!({ "added_scene": id })))
}

/// Delete a scene. **Admin only.**
async fn remove_scene(
    Session(s): Session,
    State(hub): State<Hub>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_admin(&s.role)?;
    let removed = hub.0.lock().unwrap().scenes.remove(&id).is_some();
    if removed {
        Ok(Json(json!({ "removed_scene": id })))
    } else {
        Err(ApiError::NotFound)
    }
}

/// Apply a scene: run all its steps. Any registered user may apply.
///
/// All-or-nothing — every step is validated (device exists and accepts the
/// command) before anything changes, so a broken step can't half-apply a scene.
async fn apply_scene(
    Session(_s): Session,
    State(hub): State<Hub>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut st = hub.0.lock().unwrap();
    let scene = st.scenes.get(&id).ok_or(ApiError::NotFound)?.clone();

    // Validate every step first.
    for step in &scene.steps {
        let dev = st.devices.get(&step.device).ok_or(ApiError::NotFound)?;
        dev.accepts(&step.command)?;
    }
    // Then apply — all steps are known good.
    let mut applied = Vec::new();
    for step in &scene.steps {
        let dev = st.devices.get_mut(&step.device).expect("validated above");
        dev.apply(&step.command).expect("validated above");
        actuate_radio(&step.device, dev);
        applied.push(dev.to_json(&step.device));
    }
    Ok(Json(json!({ "applied_scene": id, "name": scene.name, "devices": applied })))
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
#[derive(Debug)]
enum ApiError {
    NotFound,
    Forbidden,
    ReadOnly,
    Unsupported,
    BadLevel,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, "no such device or scene"),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "admin role required"),
            ApiError::ReadOnly => (StatusCode::BAD_REQUEST, "device is read-only"),
            ApiError::Unsupported => (StatusCode::BAD_REQUEST, "device does not support that command"),
            ApiError::BadLevel => (StatusCode::BAD_REQUEST, "level must be 0..=100"),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

// ---- glue -----------------------------------------------------------------

/// Stand-in for the radio. Replace with your 433 MHz transmit code.
fn actuate_radio(id: &str, dev: &Device) {
    eprintln!("[hub] {id} -> {}", dev.summary());
}

/// Domain-separated derivation so one `SIN_SECRET` yields a distinct session key.
fn derive_session_secret(challenge_secret: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(challenge_secret).expect("any key length");
    mac.update(b"sin-session-secret-v1");
    mac.finalize().into_bytes().to_vec()
}
