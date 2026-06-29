//! Keyward — internal CA / PKI authority (codename Citadel) for the HOLDFAST stack.
//!
//! Library root: defines [`AppState`], wires the routes via [`app`], and provides
//! [`build_dev_state`] (in-memory store + ephemeral Root CA) and [`build_state_from_env`]
//! (env-selected store + persisted Root CA). Integration tests consume [`app`] directly
//! via `tower::oneshot`, exactly like keystone.
//!
//! Endpoints:
//! - `GET  /healthz`                      liveness (public)
//! - `GET  /ca/root.crt` `/ca/bundle.pem` trust material (public)
//! - `GET  /ca/crl.pem`                   current CRL (public)
//! - `POST /ca/sign-csr`                  sign a CSR        (admin bearer)
//! - `POST /ca/issue`                     server-gen leaf   (admin bearer)
//! - `POST /ca/revoke`                    revoke a serial   (admin bearer)

pub mod auth;
pub mod ca;
pub mod config;
pub mod error;
pub mod handlers;
pub mod store;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::routing::{get, post};
use axum::Router;

use crate::ca::CaMaterial;
use crate::config::Config;
use crate::store::{InMemoryStore, PgStore, Store};

/// Shared application state. Cheap to clone (everything behind `Arc`). The Root CA
/// identity is held as PEM in [`CaMaterial`], so signing operations reconstruct an
/// `rcgen::Issuer` on demand and the state stays trivially `Send + Sync`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<dyn Store>,
    pub ca: Arc<CaMaterial>,
}

/// Build the router wiring all endpoints onto `state`.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::health::healthz))
        // --- public CA distribution ---
        .route("/ca/root.crt", get(handlers::ca::root_crt))
        .route("/ca/bundle.pem", get(handlers::ca::bundle_pem))
        .route("/ca/crl.pem", get(handlers::ca::crl_pem))
        // --- admin-guarded issuance ---
        .route("/ca/sign-csr", post(handlers::ca::sign_csr))
        .route("/ca/issue", post(handlers::ca::issue))
        .route("/ca/revoke", post(handlers::ca::revoke))
        .with_state(state)
}

/// Construct dev state: dev [`Config`], an empty [`InMemoryStore`], and an EPHEMERAL
/// Root CA (generated in memory, never persisted). Used by `main`'s memory mode and by
/// the integration tests, so they need neither a database nor a writable `CA_DIR`.
pub fn build_dev_state() -> AppState {
    let config = Config::dev();
    let ca = CaMaterial::generate(&config.ca_cn, config.ca_ttl_days)
        .expect("dev Root CA generation is valid");
    AppState {
        config: Arc::new(config),
        store: Arc::new(InMemoryStore::new()),
        ca: Arc::new(ca),
    }
}

/// Build runtime state from the environment.
///
/// [`Config`] comes from [`Config::from_env`]. The Root CA is loaded from (or generated
/// into) `CA_DIR` so the trust anchor is STABLE across restarts. The store is selected by
/// `KEYWARD_STORE`:
/// - `memory` (default): empty [`InMemoryStore`] — no database required.
/// - `postgres`: connect `DATABASE_URL`, run the idempotent migration, wire [`PgStore`].
///
/// Returns an error string on misconfiguration so `main` can fail loudly.
pub async fn build_state_from_env() -> Result<AppState, String> {
    let config = Config::from_env();

    let ca = CaMaterial::load_or_generate(
        std::path::Path::new(&config.ca_dir),
        &config.ca_cn,
        config.ca_ttl_days,
    )
    .map_err(|e| format!("load/generate Root CA in {}: {e}", config.ca_dir))?;

    let store_kind = std::env::var("KEYWARD_STORE").unwrap_or_else(|_| "memory".to_string());
    let store: Arc<dyn Store> = match store_kind.as_str() {
        "postgres" => {
            let database_url = std::env::var("DATABASE_URL")
                .map_err(|_| "KEYWARD_STORE=postgres requires DATABASE_URL".to_string())?;
            tracing::info!("KEYWARD_STORE=postgres — connecting to database");
            let pg = PgStore::connect(&database_url)
                .await
                .map_err(|e| format!("connect postgres: {e}"))?;
            pg.migrate()
                .await
                .map_err(|e| format!("run migration: {e}"))?;
            tracing::info!("postgres store ready (migrated)");
            Arc::new(pg)
        }
        "memory" => Arc::new(InMemoryStore::new()),
        other => return Err(format!("unknown KEYWARD_STORE={other} (use memory|postgres)")),
    };

    Ok(AppState {
        config: Arc::new(config),
        store,
        ca: Arc::new(ca),
    })
}

/// Current wall-clock time in epoch seconds.
pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}
