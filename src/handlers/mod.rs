//! HTTP handlers. `health` is the unauthenticated liveness probe; `ca` carries the
//! public CA-distribution endpoints (root.crt / bundle.pem / crl.pem) and the
//! admin-guarded issuance endpoints (sign-csr / issue / revoke).

pub mod ca;
pub mod health;
