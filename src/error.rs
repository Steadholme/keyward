//! JSON error envelope.
//!
//! Every failure maps to `{ "error": ..., "error_description": ... }` with the correct
//! status code; 401s additionally carry `WWW-Authenticate: Bearer`.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed request: bad CSR, unknown profile, invalid SAN, etc.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// Missing/invalid admin bearer token on a protected endpoint.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Unknown serial on revoke.
    #[error("not_found: {0}")]
    NotFound(String),

    /// Unexpected internal failure (keygen, signing, store I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str, String, bool) {
        match self {
            AppError::InvalidRequest(d) => {
                (StatusCode::BAD_REQUEST, "invalid_request", d.clone(), false)
            }
            AppError::Unauthorized(d) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", d.clone(), true)
            }
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, "not_found", d.clone(), false),
            AppError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                d.clone(),
                false,
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error, description, www_authenticate) = self.parts();
        let body = Json(serde_json::json!({
            "error": error,
            "error_description": description,
        }));
        let mut response = (status, body).into_response();
        if www_authenticate {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// CA-layer errors (rcgen / PEM / clock) collapse to a 500 server_error by default;
/// CSR parse failures surface as 400 invalid_request (see `crate::ca::CaError`).
impl From<crate::ca::CaError> for AppError {
    fn from(e: crate::ca::CaError) -> Self {
        match e {
            crate::ca::CaError::BadCsr(m) => AppError::InvalidRequest(m),
            other => AppError::Internal(other.to_string()),
        }
    }
}
