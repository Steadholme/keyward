//! Admin bearer-token authentication for the issue / sign-csr / revoke endpoints.
//!
//! `Authorization: Bearer <KEYWARD_ADMIN_TOKEN>`, compared in constant time so a
//! timing side-channel can't recover the token byte by byte. The public read-only
//! endpoints (root.crt / bundle.pem / crl.pem / healthz) do NOT call this.

use axum::http::HeaderMap;

use crate::error::AppError;

/// Verify the request carries the configured admin bearer token. Returns
/// `Unauthorized` (401 + `WWW-Authenticate: Bearer`) when the header is missing,
/// malformed, or does not match.
pub fn require_admin(headers: &HeaderMap, expected_token: &str) -> Result<(), AppError> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);

    match presented {
        Some(token) if ct_eq(token.as_bytes(), expected_token.as_bytes()) => Ok(()),
        _ => Err(AppError::Unauthorized(
            "missing or invalid admin bearer token".to_string(),
        )),
    }
}

/// Constant-time byte equality. Folds the length difference into the accumulator so
/// neither the comparison time nor an early return reveals where two values diverge.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().min(b.len());
    for i in 0..n {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_and_rejects() {
        assert!(ct_eq(b"token", b"token"));
        assert!(!ct_eq(b"token", b"tokeN"));
        assert!(!ct_eq(b"token", b"token-longer"));
        assert!(!ct_eq(b"", b"x"));
    }
}
