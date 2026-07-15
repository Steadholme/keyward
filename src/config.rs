//! Server configuration, env-driven with working dev defaults.
//!
//! Every value keeps its dev default when the corresponding env var is unset/empty,
//! so the in-memory dev path boots with NO configuration and NO database — exactly
//! like keystone. Production overrides each via the environment.

/// Default listen address (all interfaces, internal-only port 8200).
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8200";
/// Default persistent CA material directory (cert + key PEM).
pub const DEFAULT_CA_DIR: &str = "/ca";
/// Default Root CA subject common name.
pub const DEFAULT_CA_CN: &str = "Steadholme Root CA";
/// Default Root CA lifetime in days (~10 years).
pub const DEFAULT_CA_TTL_DAYS: u64 = 3650;
/// Default (and maximum) leaf certificate lifetime in days.
pub const DEFAULT_LEAF_TTL_DAYS: u64 = 90;
/// Dev/test default admin bearer token. Production MUST override `KEYWARD_ADMIN_TOKEN`.
pub const DEFAULT_ADMIN_TOKEN: &str = "keyward-dev-admin-token-change-me";

/// Runtime configuration. Cheap to clone; shared read-only behind `Arc`.
#[derive(Clone, Debug)]
pub struct Config {
    /// Listen address (`BIND_ADDR`).
    pub bind_addr: String,
    /// Directory the Root CA cert + key PEM are persisted to / reloaded from (`CA_DIR`).
    pub ca_dir: String,
    /// Root CA subject common name (`CA_CN`).
    pub ca_cn: String,
    /// Root CA lifetime in days (`CA_TTL_DAYS`).
    pub ca_ttl_days: u64,
    /// Leaf lifetime bound in days (`LEAF_TTL_DAYS`): the default when a request omits
    /// `ttl_hours`, AND the hard maximum a request may ask for.
    pub leaf_ttl_days: u64,
    /// Admin bearer token guarding issue / sign-csr / revoke (`KEYWARD_ADMIN_TOKEN`).
    pub admin_token: String,
}

impl Config {
    /// Default development configuration (in-memory, no database, no persistence).
    pub fn dev() -> Self {
        Config {
            bind_addr: DEFAULT_BIND_ADDR.to_string(),
            ca_dir: DEFAULT_CA_DIR.to_string(),
            ca_cn: DEFAULT_CA_CN.to_string(),
            ca_ttl_days: DEFAULT_CA_TTL_DAYS,
            leaf_ttl_days: DEFAULT_LEAF_TTL_DAYS,
            admin_token: DEFAULT_ADMIN_TOKEN.to_string(),
        }
    }

    /// Configuration with the dev defaults overridden by environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::dev();
        if let Some(v) = env_nonempty("BIND_ADDR") {
            config.bind_addr = v;
        }
        if let Some(v) = env_nonempty("CA_DIR") {
            config.ca_dir = v;
        }
        if let Some(v) = env_nonempty("CA_CN") {
            config.ca_cn = v;
        }
        if let Some(v) = env_nonempty("CA_TTL_DAYS").and_then(|v| v.parse().ok()) {
            config.ca_ttl_days = v;
        }
        if let Some(v) = env_nonempty("LEAF_TTL_DAYS").and_then(|v| v.parse().ok()) {
            config.leaf_ttl_days = v;
        }
        if let Some(v) = env_nonempty("KEYWARD_ADMIN_TOKEN") {
            config.admin_token = v;
        }
        config
    }

    /// Maximum leaf lifetime in hours (the `LEAF_TTL_DAYS` bound).
    pub fn max_leaf_hours(&self) -> u64 {
        self.leaf_ttl_days.saturating_mul(24).max(1)
    }

    /// Resolve a requested `ttl_hours` into the allowed window: absent/zero -> the full
    /// `LEAF_TTL_DAYS` default; otherwise clamped to `[1, max_leaf_hours]`.
    pub fn resolve_leaf_hours(&self, requested: Option<u64>) -> u64 {
        let max = self.max_leaf_hours();
        match requested {
            None | Some(0) => max,
            Some(h) => h.clamp(1, max),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::dev()
    }
}

/// Read an env var, returning `None` when unset OR empty (empty never clobbers a default).
fn env_nonempty(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}
