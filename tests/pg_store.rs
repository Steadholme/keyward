//! PostgreSQL `Store` integration test.
//!
//! Runs ONLY when `TEST_DATABASE_URL` is set (it needs an external Postgres). When unset
//! the test prints a note and returns early — it never fails the default `cargo test`
//! run, which stays database-free. Spin up a throwaway Postgres and run:
//!
//! ```text
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55434/keyward \
//!   cargo test --test pg_store -- --nocapture
//! ```
//!
//! Requires a multi-threaded runtime: the synchronous `Store` trait bridges to async
//! sqlx via `block_in_place`, which only works on the multi_thread scheduler.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use keyward::config::DEFAULT_ADMIN_TOKEN;
use keyward::store::{CertRecord, PgStore};
use keyward::{app, build_dev_state, AppState};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pg_store_full_integration() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!(
            "NOTE: TEST_DATABASE_URL not set — skipping Postgres integration test \
             (needs external Postgres). This is expected for the default test run."
        );
        return;
    };

    // --- connect / migrate (idempotent: run twice) -------------------------
    let pg = PgStore::connect(&url)
        .await
        .expect("connect to TEST_DATABASE_URL");
    pg.migrate().await.expect("migrate");
    pg.migrate().await.expect("migrate is idempotent");

    // Wire the PG store behind Arc<dyn Store> in an otherwise-dev AppState (real Root CA).
    let mut state = build_dev_state();
    state.store = Arc::new(pg);

    // --- direct Store-trait round-trip (sync over async sqlx) --------------
    let rec = CertRecord {
        serial: "0badc0de0badc0de0badc0de0badc0de".to_string(),
        common_name: "direct.internal".to_string(),
        sans: "direct.internal,10.0.0.1".to_string(),
        profile: "server".to_string(),
        not_before: 1000,
        not_after: 2000,
        revoked: false,
        revoked_at: None,
        reason: None,
        pem: "-----BEGIN CERTIFICATE-----\nXX\n-----END CERTIFICATE-----\n".to_string(),
    };
    state.store.insert_cert(rec.clone());
    // ON CONFLICT DO NOTHING — re-insert is a no-op, not an error.
    state.store.insert_cert(rec.clone());
    let got = state.store.get_cert(&rec.serial).expect("cert present");
    assert_eq!(got.common_name, "direct.internal");
    assert_eq!(got.sans, "direct.internal,10.0.0.1");
    assert!(!got.revoked);
    assert!(state.store.get_cert("ffff").is_none(), "unknown serial");

    assert!(state.store.list_revoked().is_empty(), "nothing revoked yet");
    assert!(
        state.store.revoke(&rec.serial, 1500, Some("superseded")),
        "revoke an existing serial"
    );
    assert!(!state.store.revoke("ffff", 1500, None), "revoke unknown -> false");
    let revoked = state.store.list_revoked();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].serial, rec.serial);
    assert_eq!(revoked[0].reason.as_deref(), Some("superseded"));
    let got = state.store.get_cert(&rec.serial).unwrap();
    assert!(got.revoked && got.revoked_at == Some(1500));

    // --- full HTTP flow through the PG-backed app --------------------------
    let issued = json_call(
        &state,
        post_admin(
            "/ca/issue",
            serde_json::json!({ "common_name": "svc.pg.internal", "dns_sans": ["svc.pg.internal"], "profile": "peer" }),
        ),
    )
    .await;
    let serial = issued["serial"].as_str().unwrap().to_string();
    assert!(issued["key_pem"].as_str().unwrap().contains("PRIVATE KEY"));

    // The issued cert was persisted into Postgres.
    let stored = state.store.get_cert(&serial).expect("issued cert persisted");
    assert_eq!(stored.profile, "peer");
    assert_eq!(stored.common_name, "svc.pg.internal");

    // Revoke via HTTP, then the serial shows up in the CA-signed CRL.
    let rv = json_call(
        &state,
        post_admin("/ca/revoke", serde_json::json!({ "serial": serial, "reason": "key_compromise" })),
    )
    .await;
    assert_eq!(rv["revoked"], true);

    let (status, crl_body) = raw_call(&state, get("/ca/crl.pem")).await;
    assert_eq!(status, StatusCode::OK);
    let crl_pem = String::from_utf8(crl_body).unwrap();
    assert!(crl_pem.contains("BEGIN X509 CRL"), "CRL is PEM");

    // Verify the CRL with openssl and confirm it carries the revoked serial.
    let crl_file = std::env::temp_dir().join(format!("keyward-pg-{}.crl", std::process::id()));
    std::fs::write(&crl_file, &crl_pem).unwrap();
    let out = std::process::Command::new("openssl")
        .args(["crl", "-in", crl_file.to_str().unwrap(), "-noout", "-text"])
        .output()
        .expect("openssl");
    let crl_text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(
        crl_text.contains(&serial.to_lowercase()),
        "revoked serial present in CRL from PG-backed store"
    );
    let _ = std::fs::remove_file(&crl_file);

    println!(
        "PG STORE INTEGRATION OK: migrate (idempotent) + insert/get/revoke/list round-trip \
         + full issue/revoke/CRL flow against real Postgres"
    );
}

// --- helpers ---------------------------------------------------------------------------

async fn raw_call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

async fn json_call(state: &AppState, req: Request<Body>) -> Value {
    let (status, bytes) = raw_call(state, req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200, body: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn post_admin(uri: &str, json: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {DEFAULT_ADMIN_TOKEN}"))
        .body(Body::from(json.to_string()))
        .unwrap()
}
