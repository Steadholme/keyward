//! Certificate registry storage.
//!
//! `Store` is a small trait with an in-memory and a PostgreSQL implementation, mirroring
//! keystone's seam: handlers depend only on the trait, so a FusionDB-backed store can
//! drop in later. The PostgreSQL layer uses ONLY portable standard SQL (TEXT/BIGINT/
//! BOOLEAN, PK/UNIQUE/NOT NULL/CHECK/DEFAULT, parameterized queries, INSERT .. ON
//! CONFLICT) and runtime queries (no compile-time macros), so the build needs NO
//! database and the same statements later run unchanged on FusionDB over pgwire.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::ca::RevokedEntry;

/// One issued certificate's registry row (maps 1:1 to `ca_certificates`).
#[derive(Clone, Debug)]
pub struct CertRecord {
    pub serial: String,
    pub common_name: String,
    /// Comma-joined SAN list (portable single TEXT column, no arrays).
    pub sans: String,
    pub profile: String,
    pub not_before: i64,
    pub not_after: i64,
    pub revoked: bool,
    pub revoked_at: Option<i64>,
    pub reason: Option<String>,
    /// The leaf certificate PEM (the private key is NEVER persisted).
    pub pem: String,
}

/// Pluggable certificate registry. Methods are `async`: the axum handlers `.await` them
/// directly on the serving runtime, so a registry/CRL read can never block a worker thread.
/// The in-memory store's `std::sync::Mutex` is never held across a yield point.
#[async_trait]
pub trait Store: Send + Sync {
    /// Record a newly issued certificate.
    async fn insert_cert(&self, rec: CertRecord);
    /// Look up a certificate by serial.
    async fn get_cert(&self, serial: &str) -> Option<CertRecord>;
    /// Mark a serial revoked (idempotent). Returns `true` if the serial exists.
    async fn revoke(&self, serial: &str, revoked_at: i64, reason: Option<&str>) -> bool;
    /// All revoked entries, for CRL generation.
    async fn list_revoked(&self) -> Vec<RevokedEntry>;
}

/// In-memory `Store`. `std::sync::Mutex<HashMap>` — no async lock needed. The default
/// when `KEYWARD_STORE` is unset; keeps the whole service database-free.
#[derive(Default)]
pub struct InMemoryStore {
    certs: Mutex<HashMap<String, CertRecord>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn insert_cert(&self, rec: CertRecord) {
        // The std `Mutex` is fine here: the whole critical section is synchronous (no `.await`
        // inside), so the guard is never held across a yield point.
        self.certs
            .lock()
            .expect("certs lock poisoned")
            .insert(rec.serial.clone(), rec);
    }

    async fn get_cert(&self, serial: &str) -> Option<CertRecord> {
        self.certs
            .lock()
            .expect("certs lock poisoned")
            .get(serial)
            .cloned()
    }

    async fn revoke(&self, serial: &str, revoked_at: i64, reason: Option<&str>) -> bool {
        let mut certs = self.certs.lock().expect("certs lock poisoned");
        match certs.get_mut(serial) {
            Some(rec) => {
                rec.revoked = true;
                rec.revoked_at = Some(revoked_at);
                rec.reason = reason.map(str::to_string);
                true
            }
            None => false,
        }
    }

    async fn list_revoked(&self) -> Vec<RevokedEntry> {
        self.certs
            .lock()
            .expect("certs lock poisoned")
            .values()
            .filter(|r| r.revoked)
            .map(|r| RevokedEntry {
                serial: r.serial.clone(),
                revoked_at: r.revoked_at.unwrap_or(0),
                reason: r.reason.clone(),
            })
            .collect()
    }
}

// --------------------------------------------------------------------------------------
// PostgreSQL-backed `Store` (portable: standard SQL, runtime queries, no macros).
// --------------------------------------------------------------------------------------
//
// Selected at runtime by `KEYWARD_STORE=postgres`. The `Store` trait is async, so each method
// uses sqlx natively and the handlers `.await` it on the serving runtime — there is NO
// `block_in_place` and NO sync-over-async bridge, so a registry/CRL read never blocks a worker
// thread.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

/// PostgreSQL-backed [`Store`]. Holds a `PgPool`; the async trait methods drive sqlx
/// natively, so no worker thread is ever blocked on a DB round-trip.
pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    /// Open a pooled connection. Async; call from within a Tokio runtime.
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await?;
        Ok(Self::from_pool(pool))
    }

    /// Construct from an existing pool (used by tests that share a pool).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Idempotent, portable migration. Standard SQL only — safe to run on every startup.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ca_certificates (\
                 serial TEXT PRIMARY KEY, \
                 common_name TEXT NOT NULL, \
                 sans TEXT NOT NULL, \
                 profile TEXT NOT NULL, \
                 not_before BIGINT NOT NULL, \
                 not_after BIGINT NOT NULL, \
                 revoked BOOLEAN NOT NULL DEFAULT FALSE, \
                 revoked_at BIGINT, \
                 reason TEXT, \
                 pem TEXT NOT NULL\
             )",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    fn record_from_row(row: &sqlx::postgres::PgRow) -> Result<CertRecord, sqlx::Error> {
        Ok(CertRecord {
            serial: row.try_get("serial")?,
            common_name: row.try_get("common_name")?,
            sans: row.try_get("sans")?,
            profile: row.try_get("profile")?,
            not_before: row.try_get("not_before")?,
            not_after: row.try_get("not_after")?,
            revoked: row.try_get("revoked")?,
            revoked_at: row.try_get("revoked_at")?,
            reason: row.try_get("reason")?,
            pem: row.try_get("pem")?,
        })
    }

    async fn insert_cert_async(&self, rec: &CertRecord) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO ca_certificates \
                 (serial, common_name, sans, profile, not_before, not_after, revoked, \
                  revoked_at, reason, pem) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (serial) DO NOTHING",
        )
        .bind(&rec.serial)
        .bind(&rec.common_name)
        .bind(&rec.sans)
        .bind(&rec.profile)
        .bind(rec.not_before)
        .bind(rec.not_after)
        .bind(rec.revoked)
        .bind(rec.revoked_at)
        .bind(rec.reason.as_deref())
        .bind(&rec.pem)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_cert_async(&self, serial: &str) -> Result<Option<CertRecord>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT serial, common_name, sans, profile, not_before, not_after, revoked, \
                    revoked_at, reason, pem \
             FROM ca_certificates WHERE serial = $1",
        )
        .bind(serial)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(Self::record_from_row).transpose()
    }

    async fn revoke_async(
        &self,
        serial: &str,
        revoked_at: i64,
        reason: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let res = sqlx::query(
            "UPDATE ca_certificates SET revoked = TRUE, revoked_at = $2, reason = $3 \
             WHERE serial = $1",
        )
        .bind(serial)
        .bind(revoked_at)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    async fn list_revoked_async(&self) -> Result<Vec<RevokedEntry>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT serial, revoked_at, reason FROM ca_certificates \
             WHERE revoked = TRUE ORDER BY serial",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let revoked_at: Option<i64> = row.try_get("revoked_at")?;
            out.push(RevokedEntry {
                serial: row.try_get("serial")?,
                revoked_at: revoked_at.unwrap_or(0),
                reason: row.try_get("reason")?,
            });
        }
        Ok(out)
    }
}

#[async_trait]
impl Store for PgStore {
    async fn insert_cert(&self, rec: CertRecord) {
        if let Err(e) = self.insert_cert_async(&rec).await {
            tracing::error!(error = %e, "pg insert_cert failed");
        }
    }

    async fn get_cert(&self, serial: &str) -> Option<CertRecord> {
        self.get_cert_async(serial).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg get_cert failed");
            None
        })
    }

    async fn revoke(&self, serial: &str, revoked_at: i64, reason: Option<&str>) -> bool {
        self.revoke_async(serial, revoked_at, reason)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "pg revoke failed");
                false
            })
    }

    async fn list_revoked(&self) -> Vec<RevokedEntry> {
        self.list_revoked_async().await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "pg list_revoked failed");
            Vec::new()
        })
    }
}
