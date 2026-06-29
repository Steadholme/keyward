//! CA distribution + issuance endpoints.
//!
//! Public (unauthenticated): `root.crt`, `bundle.pem`, `crl.pem` — trust material is
//! public by design. Admin-guarded (`Authorization: Bearer <KEYWARD_ADMIN_TOKEN>`):
//! `sign-csr`, `issue`, `revoke`.

use axum::extract::State;
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::require_admin;
use crate::ca::{self, IssueRequest, Profile};
use crate::error::AppError;
use crate::store::CertRecord;
use crate::{now_secs, AppState};

/// PEM media type for the cert/bundle/CRL responses.
const PEM_CONTENT_TYPE: &str = "application/x-pem-file";

fn pem_response(body: String) -> Response {
    ([(header::CONTENT_TYPE, PEM_CONTENT_TYPE)], body).into_response()
}

/// `GET /ca/root.crt` — the Root CA certificate (PEM). Public-safe trust anchor.
pub async fn root_crt(State(state): State<AppState>) -> Response {
    pem_response(state.ca.cert_pem.clone())
}

/// `GET /ca/bundle.pem` — the full trust chain (PEM). For this single-tier CA the
/// bundle is exactly the Root CA cert; the endpoint exists so consumers stay correct
/// once an intermediate is introduced.
pub async fn bundle_pem(State(state): State<AppState>) -> Response {
    pem_response(state.ca.cert_pem.clone())
}

/// `GET /ca/crl.pem` — a freshly generated, CA-signed CRL (PEM) listing every revoked
/// serial. Regenerated per request from the store so it always reflects current state.
pub async fn crl_pem(State(state): State<AppState>) -> Result<Response, AppError> {
    let revoked = state.store.list_revoked().await;
    let pem = ca::build_crl(&state.ca, &revoked)?;
    Ok(pem_response(pem))
}

// --- admin: sign-csr -------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignCsrRequest {
    pub csr_pem: String,
    #[serde(default)]
    pub ttl_hours: Option<u64>,
    #[serde(default = "default_profile")]
    pub profile: String,
}

#[derive(Serialize)]
pub struct IssuedResponse {
    pub serial: String,
    pub cert_pem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pem: Option<String>,
    pub chain_pem: String,
    pub not_before: i64,
    pub not_after: i64,
}

fn default_profile() -> String {
    "server".to_string()
}

/// `POST /ca/sign-csr` — sign a caller-supplied CSR (the requester keeps their private
/// key; PREFERRED). Keyward sets the serial, validity, basic constraints, key usage,
/// and EKUs; the CSR's subject + SANs are preserved.
pub async fn sign_csr(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SignCsrRequest>,
) -> Result<Json<IssuedResponse>, AppError> {
    require_admin(&headers, &state.config.admin_token)?;
    let profile = Profile::parse(&req.profile)?;
    let ttl_hours = state.config.resolve_leaf_hours(req.ttl_hours);

    let issued = ca::sign_csr(&state.ca, &req.csr_pem, ttl_hours, profile)?;
    persist(&state, &issued).await;

    Ok(Json(IssuedResponse {
        serial: issued.serial,
        cert_pem: issued.cert_pem,
        key_pem: None,
        chain_pem: issued.chain_pem,
        not_before: issued.not_before,
        not_after: issued.not_after,
    }))
}

// --- admin: issue (server-generated key) ----------------------------------------------

#[derive(Deserialize)]
pub struct IssueBody {
    pub common_name: String,
    #[serde(default)]
    pub dns_sans: Vec<String>,
    #[serde(default)]
    pub ip_sans: Vec<String>,
    #[serde(default)]
    pub ttl_hours: Option<u64>,
    #[serde(default = "default_profile")]
    pub profile: String,
}

/// `POST /ca/issue` — issue a leaf with a server-generated key (convenience). Returns
/// the private key in `key_pem` alongside the cert + chain.
pub async fn issue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<IssueBody>,
) -> Result<Json<IssuedResponse>, AppError> {
    require_admin(&headers, &state.config.admin_token)?;
    let profile = Profile::parse(&req.profile)?;
    let ttl_hours = state.config.resolve_leaf_hours(req.ttl_hours);

    let issued = ca::issue(
        &state.ca,
        &IssueRequest {
            common_name: req.common_name,
            dns_sans: req.dns_sans,
            ip_sans: req.ip_sans,
            ttl_hours,
            profile,
        },
    )?;
    persist(&state, &issued).await;

    Ok(Json(IssuedResponse {
        serial: issued.serial,
        cert_pem: issued.cert_pem,
        key_pem: issued.key_pem,
        chain_pem: issued.chain_pem,
        not_before: issued.not_before,
        not_after: issued.not_after,
    }))
}

// --- admin: revoke ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub serial: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct RevokeResponse {
    pub serial: String,
    pub revoked: bool,
    pub revoked_at: i64,
}

/// `POST /ca/revoke` — mark a serial revoked (idempotent). 404 if the serial is unknown.
/// The serial then appears in the next `GET /ca/crl.pem`.
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>, AppError> {
    require_admin(&headers, &state.config.admin_token)?;
    let revoked_at = now_secs();
    let ok = state
        .store
        .revoke(&req.serial, revoked_at, req.reason.as_deref())
        .await;
    if !ok {
        return Err(AppError::NotFound(format!(
            "unknown serial '{}'",
            req.serial
        )));
    }
    Ok(Json(RevokeResponse {
        serial: req.serial,
        revoked: true,
        revoked_at,
    }))
}

/// Persist an issued cert's registry row. The private key is intentionally NOT stored.
async fn persist(state: &AppState, issued: &ca::Issued) {
    state.store.insert_cert(CertRecord {
        serial: issued.serial.clone(),
        common_name: issued.common_name.clone(),
        sans: issued.sans.clone(),
        profile: issued.profile.clone(),
        not_before: issued.not_before,
        not_after: issued.not_after,
        revoked: false,
        revoked_at: None,
        reason: None,
        pem: issued.cert_pem.clone(),
    })
    .await;
}
