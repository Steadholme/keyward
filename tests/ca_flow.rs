//! End-to-end CA contract test against the in-memory store (NO database, NO disk CA).
//!
//! Drives the real Router in-process via `tower::oneshot` and verifies the issued
//! material with the system `openssl` (chain verification, EKU profiles, CRL revocation)
//! — the same way an external relying party would.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use keyward::config::DEFAULT_ADMIN_TOKEN;
use keyward::{app, build_dev_state, AppState};
use serde_json::Value;
use std::io::Write;
use std::process::Command;
use tower::ServiceExt;

// --- HTTP helpers ----------------------------------------------------------------------

async fn call(state: &AppState, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app(state.clone()).oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
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

// --- openssl helpers -------------------------------------------------------------------

fn tmp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "keyward-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn write_file(path: &std::path::Path, content: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

fn openssl(args: &[&str]) -> (bool, String) {
    let out = Command::new("openssl")
        .args(args)
        .output()
        .expect("openssl must be installed for the test");
    let mut combined = String::from_utf8_lossy(&out.stdout).to_string();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), combined)
}

/// Decode the JSON body, failing loudly with the raw body if it isn't 200/JSON.
fn json_ok(status: StatusCode, body: &[u8]) -> Value {
    assert_eq!(
        status,
        StatusCode::OK,
        "expected 200, body: {}",
        String::from_utf8_lossy(body)
    );
    serde_json::from_slice(body).expect("response is JSON")
}

// --- tests -----------------------------------------------------------------------------

#[tokio::test]
async fn healthz_ok() {
    let state = build_dev_state();
    let (status, body) = call(&state, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body, b"ok");
}

#[tokio::test]
async fn root_crt_is_a_ca() {
    let state = build_dev_state();
    let (status, body) = call(&state, get("/ca/root.crt")).await;
    assert_eq!(status, StatusCode::OK);
    let pem = String::from_utf8(body).unwrap();
    assert!(pem.contains("BEGIN CERTIFICATE"), "root.crt is PEM");

    let root = tmp_path("root.crt");
    write_file(&root, &pem);
    let (ok, text) = openssl(&["x509", "-in", root.to_str().unwrap(), "-noout", "-text"]);
    assert!(ok, "openssl parsed root: {text}");
    assert!(text.contains("CA:TRUE"), "root has CA:TRUE: {text}");
    assert!(
        text.contains("Certificate Sign") && text.contains("CRL Sign"),
        "root keyUsage has keyCertSign + cRLSign: {text}"
    );

    // bundle.pem is the chain (the root, here).
    let (status, bundle) = call(&state, get("/ca/bundle.pem")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(bundle).unwrap().contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn issue_server_leaf_chains_to_root_and_has_server_eku() {
    let state = build_dev_state();

    // fetch root for the CAfile
    let (_, root_body) = call(&state, get("/ca/root.crt")).await;
    let root = tmp_path("root.crt");
    write_file(&root, &String::from_utf8(root_body).unwrap());

    // issue a server leaf (server-generated key)
    let (status, body) = call(
        &state,
        post_admin(
            "/ca/issue",
            serde_json::json!({
                "common_name": "svc.holdfast.internal",
                "dns_sans": ["svc.holdfast.internal", "svc"],
                "ip_sans": ["127.0.0.1"],
                "ttl_hours": 48,
                "profile": "server"
            }),
        ),
    )
    .await;
    let v = json_ok(status, &body);
    assert!(!v["serial"].as_str().unwrap().is_empty());
    assert!(v["key_pem"].as_str().unwrap().contains("PRIVATE KEY"), "issue returns a key");
    let cert_pem = v["cert_pem"].as_str().unwrap();
    let chain_pem = v["chain_pem"].as_str().unwrap();
    assert!(chain_pem.matches("BEGIN CERTIFICATE").count() >= 2, "chain has leaf + root");

    let leaf = tmp_path("leaf.crt");
    write_file(&leaf, cert_pem);

    // chain verification
    let (ok, text) = openssl(&[
        "verify",
        "-CAfile",
        root.to_str().unwrap(),
        leaf.to_str().unwrap(),
    ]);
    assert!(ok, "leaf chains to root: {text}");

    // EKU = serverAuth, plus SANs present
    let (_, text) = openssl(&["x509", "-in", leaf.to_str().unwrap(), "-noout", "-text"]);
    assert!(text.contains("TLS Web Server Authentication"), "serverAuth EKU: {text}");
    assert!(!text.contains("TLS Web Client Authentication"), "no clientAuth for server: {text}");
    assert!(text.contains("DNS:svc.holdfast.internal"), "DNS SAN present: {text}");
    assert!(text.contains("IP Address:127.0.0.1"), "IP SAN present: {text}");
    // A non-CA leaf omits BasicConstraints entirely (valid: absence => not a CA), so we
    // assert it is NOT marked as a CA rather than expecting an explicit CA:FALSE.
    assert!(!text.contains("CA:TRUE"), "leaf must not be a CA: {text}");
}

#[tokio::test]
async fn client_and_peer_profiles_set_correct_ekus() {
    let state = build_dev_state();

    for (profile, want_server, want_client) in [
        ("client", false, true),
        ("peer", true, true),
    ] {
        let (status, body) = call(
            &state,
            post_admin(
                "/ca/issue",
                serde_json::json!({ "common_name": format!("{profile}.internal"), "profile": profile }),
            ),
        )
        .await;
        let v = json_ok(status, &body);
        let leaf = tmp_path(&format!("{profile}.crt"));
        write_file(&leaf, v["cert_pem"].as_str().unwrap());
        let (_, text) = openssl(&["x509", "-in", leaf.to_str().unwrap(), "-noout", "-text"]);
        assert_eq!(
            text.contains("TLS Web Server Authentication"),
            want_server,
            "{profile} serverAuth: {text}"
        );
        assert_eq!(
            text.contains("TLS Web Client Authentication"),
            want_client,
            "{profile} clientAuth: {text}"
        );
    }
}

#[tokio::test]
async fn sign_csr_preserves_subject_and_chains() {
    use rcgen::{CertificateParams, DnType, KeyPair};
    let state = build_dev_state();

    let (_, root_body) = call(&state, get("/ca/root.crt")).await;
    let root = tmp_path("root.crt");
    write_file(&root, &String::from_utf8(root_body).unwrap());

    // Build a CSR with rcgen (requester's own key stays local).
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["keystone.holdfast.internal".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "keystone.holdfast.internal");
    let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();

    let (status, body) = call(
        &state,
        post_admin(
            "/ca/sign-csr",
            serde_json::json!({ "csr_pem": csr_pem, "ttl_hours": 24, "profile": "peer" }),
        ),
    )
    .await;
    let v = json_ok(status, &body);
    assert!(v["key_pem"].is_null(), "sign-csr never returns a key");
    let leaf = tmp_path("csr-leaf.crt");
    write_file(&leaf, v["cert_pem"].as_str().unwrap());

    let (ok, text) = openssl(&[
        "verify",
        "-CAfile",
        root.to_str().unwrap(),
        leaf.to_str().unwrap(),
    ]);
    assert!(ok, "CSR-signed leaf chains to root: {text}");

    let (_, text) = openssl(&["x509", "-in", leaf.to_str().unwrap(), "-noout", "-text"]);
    assert!(text.contains("CN = keystone.holdfast.internal") || text.contains("CN=keystone.holdfast.internal"), "subject preserved: {text}");
    assert!(text.contains("DNS:keystone.holdfast.internal"), "CSR SAN preserved: {text}");
    assert!(text.contains("TLS Web Server Authentication") && text.contains("TLS Web Client Authentication"), "peer EKUs: {text}");
}

#[tokio::test]
async fn revoke_appears_in_crl_and_openssl_crl_check_fails() {
    let state = build_dev_state();

    let (_, root_body) = call(&state, get("/ca/root.crt")).await;
    let root = tmp_path("root.crt");
    write_file(&root, &String::from_utf8(root_body).unwrap());

    // issue, then revoke
    let (status, body) = call(
        &state,
        post_admin("/ca/issue", serde_json::json!({ "common_name": "doomed.internal", "profile": "server" })),
    )
    .await;
    let v = json_ok(status, &body);
    let serial = v["serial"].as_str().unwrap().to_string();
    let leaf = tmp_path("doomed.crt");
    write_file(&leaf, v["cert_pem"].as_str().unwrap());

    // CRL before revocation: cert should pass -crl_check
    let crl_before = tmp_path("before.crl");
    let (_, crl_body) = call(&state, get("/ca/crl.pem")).await;
    write_file(&crl_before, &String::from_utf8(crl_body).unwrap());
    let (ok_before, _t) = openssl(&[
        "verify", "-crl_check", "-CAfile", root.to_str().unwrap(),
        "-CRLfile", crl_before.to_str().unwrap(), leaf.to_str().unwrap(),
    ]);
    assert!(ok_before, "non-revoked cert passes crl_check");

    // revoke
    let (status, body) = call(
        &state,
        post_admin("/ca/revoke", serde_json::json!({ "serial": serial, "reason": "key_compromise" })),
    )
    .await;
    let rv = json_ok(status, &body);
    assert_eq!(rv["revoked"], true);

    // CRL now lists the serial
    let crl_after = tmp_path("after.crl");
    let (_, crl_body) = call(&state, get("/ca/crl.pem")).await;
    write_file(&crl_after, &String::from_utf8(crl_body).unwrap());
    let (ok, crl_text) = openssl(&["crl", "-in", crl_after.to_str().unwrap(), "-noout", "-text"]);
    assert!(ok, "openssl parses CRL: {crl_text}");
    // openssl prints serials uppercase; compare case-insensitively.
    assert!(
        crl_text.to_lowercase().contains(&serial.to_lowercase()),
        "revoked serial {serial} present in CRL:\n{crl_text}"
    );

    // -crl_check now fails with "certificate revoked"
    let (ok_after, text_after) = openssl(&[
        "verify", "-crl_check", "-CAfile", root.to_str().unwrap(),
        "-CRLfile", crl_after.to_str().unwrap(), leaf.to_str().unwrap(),
    ]);
    assert!(!ok_after, "revoked cert must FAIL crl_check: {text_after}");
    assert!(text_after.to_lowercase().contains("revoked"), "reason is revocation: {text_after}");
}

#[tokio::test]
async fn admin_endpoints_require_bearer_token() {
    let state = build_dev_state();

    // no auth header
    let req = Request::builder()
        .method("POST")
        .uri("/ca/issue")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "common_name": "x.internal" }).to_string(),
        ))
        .unwrap();
    let (status, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "missing bearer -> 401");

    // wrong token
    let req = Request::builder()
        .method("POST")
        .uri("/ca/issue")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, "Bearer wrong-token")
        .body(Body::from(
            serde_json::json!({ "common_name": "x.internal" }).to_string(),
        ))
        .unwrap();
    let (status, _) = call(&state, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong bearer -> 401");

    // public endpoints stay open
    let (status, _) = call(&state, get("/ca/root.crt")).await;
    assert_eq!(status, StatusCode::OK, "root.crt is public");
}
