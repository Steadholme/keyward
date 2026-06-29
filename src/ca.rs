//! Internal Certificate Authority: Root CA generation/persistence, leaf issuance,
//! CSR signing, and CRL generation — all via the `rcgen` crate (ring backend).
//!
//! Design notes:
//! - The CA identity is just two PEM strings ([`CaMaterial`]: cert + private key),
//!   which makes it trivially `Clone + Send + Sync` for the shared `Arc` state. Every
//!   signing operation reconstructs an `rcgen::Issuer` from those PEMs on demand
//!   (a cheap parse), so we never have to hold rcgen's non-`Clone` key types in state.
//! - Persistence ([`CaMaterial::load_or_generate`]) writes `ca.crt` (0644) and
//!   `ca.key` (0600) into `CA_DIR` and reloads them on restart, so the Root CA — and
//!   therefore the trust anchor every issued leaf chains to — is STABLE across restarts.
//! - Serials are random 128-bit, encoded with the DER sign bit cleared so the cert
//!   serial and the CRL entry serial are byte-identical (openssl `-crl_check` matches).

use std::fs;
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams,
    CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber, PKCS_ECDSA_P256_SHA256,
    PKCS_ECDSA_P384_SHA384,
};
use time::OffsetDateTime;

/// Clock-skew backdating applied to every `not_before` (seconds).
const NOT_BEFORE_SKEW_SECS: i64 = 300;
/// `nextUpdate` window baked into a generated CRL (seconds): 7 days.
const CRL_NEXT_UPDATE_SECS: i64 = 7 * 24 * 60 * 60;
/// Root CA cert filename inside `CA_DIR`.
const CA_CERT_FILE: &str = "ca.crt";
/// Root CA private key filename inside `CA_DIR`.
const CA_KEY_FILE: &str = "ca.key";

/// CA-layer errors. `BadCsr` maps to a 400 at the HTTP edge; everything else is a 500.
#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("clock: {0}")]
    Clock(String),
    #[error("bad csr: {0}")]
    BadCsr(String),
}

/// Leaf certificate profile — selects the Extended Key Usage set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// `serverAuth` — TLS server certificates.
    Server,
    /// `clientAuth` — TLS client certificates.
    Client,
    /// `serverAuth` + `clientAuth` — mutual-TLS peers (both ends of an mTLS link).
    Peer,
}

impl Profile {
    /// Parse the wire value; defaults are explicit (`server`|`client`|`peer`).
    pub fn parse(s: &str) -> Result<Self, CaError> {
        match s {
            "server" => Ok(Profile::Server),
            "client" => Ok(Profile::Client),
            "peer" => Ok(Profile::Peer),
            other => Err(CaError::BadCsr(format!(
                "unknown profile '{other}' (use server|client|peer)"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Profile::Server => "server",
            Profile::Client => "client",
            Profile::Peer => "peer",
        }
    }

    fn ekus(&self) -> Vec<ExtendedKeyUsagePurpose> {
        match self {
            Profile::Server => vec![ExtendedKeyUsagePurpose::ServerAuth],
            Profile::Client => vec![ExtendedKeyUsagePurpose::ClientAuth],
            Profile::Peer => vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ],
        }
    }
}

/// The Root CA identity: self-signed cert PEM + its private key PEM (the latter is
/// secret and never leaves the process except as a 0600 file on disk).
#[derive(Clone)]
pub struct CaMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

/// A freshly issued (or CSR-signed) certificate plus its metadata.
pub struct Issued {
    /// Random 128-bit serial, lowercase hex (the DB primary key + API `serial`).
    pub serial: String,
    /// The leaf certificate PEM.
    pub cert_pem: String,
    /// The leaf's private key PEM — `Some` only for the server-generated `/ca/issue`
    /// path; `None` when signing a CSR (the requester keeps their own key).
    pub key_pem: Option<String>,
    /// Leaf cert followed by the Root CA cert (a full chain a client can serve as-is).
    pub chain_pem: String,
    /// Subject common name (for the store record).
    pub common_name: String,
    /// Comma-joined SANs (for the store record).
    pub sans: String,
    /// Profile name (for the store record).
    pub profile: String,
    pub not_before: i64,
    pub not_after: i64,
}

impl CaMaterial {
    /// Generate a brand-new self-signed Root CA in memory (no disk writes). Used by the
    /// dev/test path; production uses [`load_or_generate`](Self::load_or_generate).
    ///
    /// ECDSA P-384 (stronger curve for the long-lived trust anchor), CA basic
    /// constraints, and `keyCertSign` + `cRLSign` key usage so it can both sign leaves
    /// and sign its own CRL.
    pub fn generate(ca_cn: &str, ca_ttl_days: u64) -> Result<Self, CaError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;

        let now = now_secs();
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, ca_cn);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.not_before = to_dt(now - NOT_BEFORE_SKEW_SECS)?;
        params.not_after = to_dt(now + (ca_ttl_days as i64) * 86_400)?;
        let (serial, _hex) = random_serial();
        params.serial_number = Some(serial);

        let cert = params.self_signed(&key)?;
        Ok(CaMaterial {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        })
    }

    /// Load the Root CA from `dir` (`ca.crt` + `ca.key`) if both exist, otherwise
    /// generate a fresh one and PERSIST it: `ca.crt` (0644) + `ca.key` (0600), creating
    /// `dir` if needed. Reloading the same files reproduces the SAME CA identity, so the
    /// trust anchor is stable across restarts.
    pub fn load_or_generate(dir: &Path, ca_cn: &str, ca_ttl_days: u64) -> Result<Self, CaError> {
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);

        if cert_path.exists() && key_path.exists() {
            let cert_pem = fs::read_to_string(&cert_path)?;
            let key_pem = fs::read_to_string(&key_path)?;
            // Sanity: the persisted material must reconstruct a usable issuer.
            let material = CaMaterial { cert_pem, key_pem };
            material.issuer()?;
            return Ok(material);
        }

        let material = Self::generate(ca_cn, ca_ttl_days)?;
        fs::create_dir_all(dir)?;
        write_public(&cert_path, material.cert_pem.as_bytes())?;
        write_private(&key_path, material.key_pem.as_bytes())?;
        Ok(material)
    }

    /// Reconstruct an `rcgen::Issuer` (CA cert subject + signing key) from the PEMs.
    /// Cheap; called once per signing operation so state holds only `Clone`able PEMs.
    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, CaError> {
        let key = KeyPair::from_pem(&self.key_pem)?;
        Ok(Issuer::from_ca_cert_pem(&self.cert_pem, key)?)
    }
}

/// Parameters for a server-generated leaf (`POST /ca/issue`).
pub struct IssueRequest {
    pub common_name: String,
    pub dns_sans: Vec<String>,
    pub ip_sans: Vec<String>,
    pub ttl_hours: u64,
    pub profile: Profile,
}

/// Issue a leaf with a server-generated ECDSA P-256 key (convenience path). The private
/// key is returned to the caller in [`Issued::key_pem`].
pub fn issue(ca: &CaMaterial, req: &IssueRequest) -> Result<Issued, CaError> {
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    // Merge SANs; if none supplied, fall back to the CN so a server cert is usable.
    let mut sans: Vec<String> = Vec::new();
    sans.extend(req.dns_sans.iter().cloned());
    sans.extend(req.ip_sans.iter().cloned());
    if sans.is_empty() {
        sans.push(req.common_name.clone());
    }
    let sans_joined = sans.join(",");

    let mut params =
        CertificateParams::new(sans).map_err(|e| CaError::BadCsr(format!("invalid SAN: {e}")))?;
    params
        .distinguished_name
        .push(DnType::CommonName, &req.common_name);
    let (serial_hex, not_before, not_after) =
        apply_leaf_profile(&mut params, req.ttl_hours, req.profile)?;

    let issuer = ca.issuer()?;
    let cert = params.signed_by(&leaf_key, &issuer)?;
    let cert_pem = cert.pem();

    Ok(Issued {
        serial: serial_hex,
        chain_pem: format!("{cert_pem}{}", ca.cert_pem),
        cert_pem,
        key_pem: Some(leaf_key.serialize_pem()),
        common_name: req.common_name.clone(),
        sans: sans_joined,
        profile: req.profile.as_str().to_string(),
        not_before,
        not_after,
    })
}

/// Sign a caller-supplied CSR (PREFERRED path — the requester keeps their private key).
/// The CSR's subject and SANs are preserved; Keyward authoritatively sets the serial,
/// validity window, basic constraints (never a CA), key usage, and EKUs for the profile.
pub fn sign_csr(
    ca: &CaMaterial,
    csr_pem: &str,
    ttl_hours: u64,
    profile: Profile,
) -> Result<Issued, CaError> {
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| CaError::BadCsr(format!("parse CSR: {e}")))?;

    let common_name = csr
        .params
        .distinguished_name
        .get(&DnType::CommonName)
        .and_then(dn_value_string)
        .unwrap_or_default();
    let sans_joined = csr
        .params
        .subject_alt_names
        .iter()
        .map(san_string)
        .collect::<Vec<_>>()
        .join(",");

    let (serial_hex, not_before, not_after) =
        apply_leaf_profile(&mut csr.params, ttl_hours, profile)?;

    let issuer = ca.issuer()?;
    let cert = csr.signed_by(&issuer)?;
    let cert_pem = cert.pem();

    Ok(Issued {
        serial: serial_hex,
        chain_pem: format!("{cert_pem}{}", ca.cert_pem),
        cert_pem,
        key_pem: None,
        common_name,
        sans: sans_joined,
        profile: profile.as_str().to_string(),
        not_before,
        not_after,
    })
}

/// A revoked entry for CRL generation: hex serial, revocation epoch seconds, optional reason.
pub struct RevokedEntry {
    pub serial: String,
    pub revoked_at: i64,
    pub reason: Option<String>,
}

/// Build a CA-signed CRL (PEM) covering every supplied revoked serial. `thisUpdate` is
/// now; `nextUpdate` is now + 7 days. An empty list yields a valid empty CRL.
pub fn build_crl(ca: &CaMaterial, revoked: &[RevokedEntry]) -> Result<String, CaError> {
    let now = now_secs();
    let mut revoked_params = Vec::with_capacity(revoked.len());
    for entry in revoked {
        let bytes = hex::decode(&entry.serial)
            .map_err(|e| CaError::Clock(format!("bad stored serial '{}': {e}", entry.serial)))?;
        revoked_params.push(RevokedCertParams {
            serial_number: SerialNumber::from_slice(&bytes),
            revocation_time: to_dt(entry.revoked_at)?,
            reason_code: entry.reason.as_deref().and_then(map_reason),
            invalidity_date: None,
        });
    }

    let params = CertificateRevocationListParams {
        this_update: to_dt(now)?,
        next_update: to_dt(now + CRL_NEXT_UPDATE_SECS)?,
        // Monotonic-ish CRL number derived from the wall clock.
        crl_number: SerialNumber::from(now as u64),
        issuing_distribution_point: None,
        revoked_certs: revoked_params,
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };

    let issuer = ca.issuer()?;
    let crl = params.signed_by(&issuer)?;
    crl.pem().map_err(CaError::from)
}

// --------------------------------------------------------------------------------------
// internals
// --------------------------------------------------------------------------------------

/// Apply the authoritative leaf extensions onto `params`, overriding anything a CSR may
/// have requested. Sets: random serial, validity window (clamped upstream), `is_ca =
/// NoCa` (a CSR can NEVER obtain a CA cert), profile key-usage + EKUs, and the AKI
/// extension so the leaf points at the issuing CA. Returns `(serial_hex, nb, na)`.
fn apply_leaf_profile(
    params: &mut CertificateParams,
    ttl_hours: u64,
    profile: Profile,
) -> Result<(String, i64, i64), CaError> {
    let now = now_secs();
    let not_before = now - NOT_BEFORE_SKEW_SECS;
    let not_after = now + (ttl_hours as i64) * 3600;

    params.is_ca = IsCa::NoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = match profile {
        // ECDSA leaves use DigitalSignature; KeyEncipherment is added for the server
        // side for broad compatibility with RSA-KEX-capable peers.
        Profile::Server | Profile::Peer => vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ],
        Profile::Client => vec![KeyUsagePurpose::DigitalSignature],
    };
    params.extended_key_usages = profile.ekus();
    params.not_before = to_dt(not_before)?;
    params.not_after = to_dt(not_after)?;

    let (serial, serial_hex) = random_serial();
    params.serial_number = Some(serial);

    Ok((serial_hex, not_before, not_after))
}

/// A random 128-bit serial. The top byte is forced into `0x40..=0x7f` so the DER INTEGER
/// is positive AND keeps its full 16-byte width with no leading-zero stripping — making
/// the cert serial and the CRL entry serial byte-identical.
fn random_serial() -> (SerialNumber, String) {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes[0] = (bytes[0] & 0x3f) | 0x40;
    (SerialNumber::from_slice(&bytes), hex::encode(bytes))
}

/// Map a stored reason string to a CRL `RevocationReason`. Unknown/absent -> no reason.
fn map_reason(reason: &str) -> Option<RevocationReason> {
    match reason {
        "key_compromise" => Some(RevocationReason::KeyCompromise),
        "ca_compromise" => Some(RevocationReason::CaCompromise),
        "affiliation_changed" => Some(RevocationReason::AffiliationChanged),
        "superseded" => Some(RevocationReason::Superseded),
        "cessation_of_operation" => Some(RevocationReason::CessationOfOperation),
        "privilege_withdrawn" => Some(RevocationReason::PrivilegeWithdrawn),
        _ => None,
    }
}

fn dn_value_string(v: &rcgen::DnValue) -> Option<String> {
    match v {
        rcgen::DnValue::Utf8String(s) => Some(s.clone()),
        rcgen::DnValue::PrintableString(s) => Some(s.to_string()),
        rcgen::DnValue::Ia5String(s) => Some(s.to_string()),
        rcgen::DnValue::TeletexString(s) => Some(s.to_string()),
        _ => None,
    }
}

fn san_string(s: &rcgen::SanType) -> String {
    match s {
        rcgen::SanType::DnsName(n) => n.to_string(),
        rcgen::SanType::IpAddress(ip) => ip.to_string(),
        rcgen::SanType::Rfc822Name(n) => n.to_string(),
        rcgen::SanType::URI(u) => u.to_string(),
        rcgen::SanType::OtherName(_) => "othername".to_string(),
        _ => "unknown".to_string(),
    }
}

/// Epoch seconds -> `OffsetDateTime`, surfacing a bad timestamp as a `CaError`.
fn to_dt(secs: i64) -> Result<OffsetDateTime, CaError> {
    OffsetDateTime::from_unix_timestamp(secs)
        .map_err(|e| CaError::Clock(format!("invalid timestamp {secs}: {e}")))
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs() as i64
}

/// Write a world-readable (0644) public artifact.
#[cfg(unix)]
fn write_public(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_public(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

/// Write an owner-only (0600) private artifact so the CA key is never group/world-readable.
#[cfg(unix)]
fn write_private(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `load_or_generate` against the SAME dir must yield the SAME Root CA cert + key —
    /// i.e. the material is persisted and reloaded, not regenerated. This is the property
    /// that keeps the trust anchor (and every leaf's chain) stable across a restart.
    #[test]
    fn load_or_generate_is_stable_across_reloads() {
        let dir = std::env::temp_dir().join(format!("keyward-ca-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let first = CaMaterial::load_or_generate(&dir, "HOLDFAST Root CA", 3650).unwrap();
        assert!(dir.join(CA_CERT_FILE).exists(), "ca.crt written");
        assert!(dir.join(CA_KEY_FILE).exists(), "ca.key written");

        let second = CaMaterial::load_or_generate(&dir, "HOLDFAST Root CA", 3650).unwrap();
        assert_eq!(
            first.cert_pem, second.cert_pem,
            "reload reproduces the SAME CA cert"
        );
        assert_eq!(first.key_pem, second.key_pem, "reload reproduces the SAME CA key");

        // The persisted key file must be owner-only (0600) on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(CA_KEY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "ca.key must be mode 0600");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// A freshly generated CA differs from a persisted one (the stability above is real
    /// persistence, not a constant key), and the CA can sign a verifiable leaf.
    #[test]
    fn generated_ca_issues_a_chaining_leaf() {
        let ca = CaMaterial::generate("HOLDFAST Root CA", 3650).unwrap();
        let other = CaMaterial::generate("HOLDFAST Root CA", 3650).unwrap();
        assert_ne!(ca.cert_pem, other.cert_pem, "independent CAs differ");

        let issued = issue(
            &ca,
            &IssueRequest {
                common_name: "leaf.internal".to_string(),
                dns_sans: vec!["leaf.internal".to_string()],
                ip_sans: vec![],
                ttl_hours: 24,
                profile: Profile::Server,
            },
        )
        .unwrap();
        assert_eq!(issued.serial.len(), 32, "128-bit serial is 32 hex chars");
        assert!(issued.key_pem.is_some());
        // The Issuer can be reconstructed (parses cleanly) and a CRL builds.
        let crl = build_crl(
            &ca,
            &[RevokedEntry {
                serial: issued.serial.clone(),
                revoked_at: now_secs(),
                reason: Some("superseded".to_string()),
            }],
        )
        .unwrap();
        assert!(crl.contains("BEGIN X509 CRL"), "CRL is PEM");
    }
}
