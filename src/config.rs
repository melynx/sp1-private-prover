use std::{collections::HashSet, net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Allowlist,
    Denylist,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub active_global: usize,
    pub active_per_signer: usize,
    pub queued_per_signer: usize,
    pub queued_global: usize,
    pub max_elf_bytes: u64,
    pub max_artifact_compressed_bytes: u64,
    pub max_artifact_expanded_bytes: u64,
    pub max_cycles: u64,
    pub max_gas: u64,
    pub max_deadline: DurationDef,
    pub retained_bytes: u64,
    pub upload_expiry: DurationDef,
    pub terminal_retention: DurationDef,
    pub proof_url_expiry: DurationDef,
    pub gtt_guard_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            active_global: 1,
            active_per_signer: 1,
            queued_per_signer: 4,
            queued_global: 32,
            max_elf_bytes: 64 * 1024 * 1024,
            max_artifact_compressed_bytes: 256 * 1024 * 1024,
            max_artifact_expanded_bytes: 512 * 1024 * 1024,
            max_cycles: 1_000_000_000_000,
            max_gas: 1_000_000_000,
            max_deadline: DurationDef(4 * 60 * 60),
            retained_bytes: 256 * 1024 * 1024 * 1024,
            upload_expiry: DurationDef(15 * 60),
            terminal_retention: DurationDef(24 * 60 * 60),
            proof_url_expiry: DurationDef(15 * 60),
            gtt_guard_bytes: 40 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DurationDef(pub u64);

impl<'de> Deserialize<'de> for DurationDef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        humantime::parse_duration(&value)
            .map(|duration| Self(duration.as_secs()))
            .map_err(serde::de::Error::custom)
    }
}

impl DurationDef {
    pub const fn duration(self) -> Duration {
        Duration::from_secs(self.0)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub grpc_listen: SocketAddr,
    pub http_listen: SocketAddr,
    pub public_http_base: String,
    pub state_dir: PathBuf,
    pub access_mode: AccessMode,
    pub signer_addresses: HashSet<String>,
    pub limits: Limits,
    pub rocm_server: PathBuf,
    pub rocm_server_sha256: String,
    pub circuit_cache: PathBuf,
    pub circuit_hashes: PathBuf,
    pub render_node: Option<PathBuf>,
    pub gtt_path: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            grpc_listen: "0.0.0.0:50051".parse().unwrap(),
            http_listen: "0.0.0.0:8080".parse().unwrap(),
            public_http_base: "http://127.0.0.1:8080".into(),
            state_dir: "/var/lib/sp1-private-prover".into(),
            access_mode: AccessMode::Allowlist,
            signer_addresses: HashSet::new(),
            limits: Limits::default(),
            rocm_server: "/usr/local/bin/sp1-rocm-server".into(),
            rocm_server_sha256: "942ce14d2d7474ca58c081b0b46b404df1cff76398bb1c5077e6764af7acde72"
                .into(),
            circuit_cache: "/var/cache/sp1/circuits".into(),
            circuit_hashes: "/var/cache/sp1/circuits/SHA256SUMS.extracted".into(),
            render_node: None,
            gtt_path: None,
            tls_cert: None,
            tls_key: None,
        }
    }
}

#[derive(Debug, Parser)]
pub struct Args {
    #[arg(
        long,
        env = "SP1_PRIVATE_PROVER_CONFIG",
        default_value = "/etc/sp1-private-prover/config.toml"
    )]
    pub config: PathBuf,
    #[arg(long, hide = true)]
    pub healthcheck: bool,
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read configuration {}", path.display()))?;
        let text = std::str::from_utf8(&bytes).context("configuration is not UTF-8")?;
        let config: Self = toml::from_str(text).context("parse configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.public_http_base).context("parse public_http_base")?;
        if url.scheme() != "http" && url.scheme() != "https" {
            bail!("public_http_base must use http or https");
        }
        if self.limits.active_global != 1 {
            bail!("limits.active_global must be 1 because one ROCm prover is supervised");
        }
        if self.limits.gtt_guard_bytes == 0 {
            bail!("limits.gtt_guard_bytes must not be zero");
        }
        if std::env::var("SP1_ROCM_ALLOCATOR").as_deref() == Ok("arena") {
            bail!("SP1_ROCM_ALLOCATOR=arena is not supported for service operation");
        }
        match (&self.tls_cert, &self.tls_key) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => bail!("tls_cert and tls_key must be configured together"),
        }
        Ok(())
    }

    pub fn signer_allowed(&self, address: &str) -> bool {
        let address = address.to_ascii_lowercase();
        match self.access_mode {
            AccessMode::Allowlist => self.signer_addresses.contains(&address),
            AccessMode::Denylist => !self.signer_addresses.contains(&address),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_denies_and_empty_denylist_allows() {
        let mut config = Config::default();
        assert!(!config.signer_allowed("0x0000000000000000000000000000000000000001"));
        config.access_mode = AccessMode::Denylist;
        assert!(config.signer_allowed("0x0000000000000000000000000000000000000001"));
    }
}
