use std::{fs, sync::Arc};

#[cfg(feature = "rocm")]
use std::{collections::HashMap, fs::OpenOptions, process::Stdio, time::Duration};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Stdin};
#[cfg(feature = "rocm")]
use sp1_sdk::{ProofFromNetwork, ProveRequest};
#[cfg(feature = "rocm")]
use tokio::{
    net::UnixStream,
    process::{Child, Command},
    sync::Mutex,
};

use crate::{config::Config, proto::network::ProofMode};

#[derive(Debug, Clone)]
pub struct DerivedProgram {
    pub vk_hash: Vec<u8>,
    pub vk: Vec<u8>,
}

#[async_trait]
pub trait ProofEngine: Send + Sync {
    async fn derive_program(&self, elf: &[u8]) -> Result<DerivedProgram>;
    async fn prove(
        &self,
        vk_hash: &[u8],
        elf: &[u8],
        stdin: SP1Stdin,
        mode: ProofMode,
    ) -> Result<Vec<u8>>;
    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }
}

pub struct UnavailableEngine(pub String);

#[async_trait]
impl ProofEngine for UnavailableEngine {
    async fn derive_program(&self, _elf: &[u8]) -> Result<DerivedProgram> {
        bail!("proof engine unavailable: {}", self.0)
    }
    async fn prove(
        &self,
        _vk_hash: &[u8],
        _elf: &[u8],
        _stdin: SP1Stdin,
        _mode: ProofMode,
    ) -> Result<Vec<u8>> {
        bail!("proof engine unavailable: {}", self.0)
    }
}

pub fn verify_runtime_assets(config: &Config) -> Result<()> {
    let bytes = fs::read(&config.rocm_server)
        .with_context(|| format!("read exact ROCm server {}", config.rocm_server.display()))?;
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != config.rocm_server_sha256.to_ascii_lowercase() {
        bail!(
            "ROCm server SHA-256 mismatch: expected {}, received {actual}",
            config.rocm_server_sha256
        );
    }
    verify_hash_manifest(&config.circuit_cache, &config.circuit_hashes)
}

fn verify_hash_manifest(root: &std::path::Path, manifest: &std::path::Path) -> Result<()> {
    let text = fs::read_to_string(manifest)
        .with_context(|| format!("read circuit hash manifest {}", manifest.display()))?;
    if text.lines().all(|line| line.trim().is_empty()) {
        bail!("circuit hash manifest is empty");
    }
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (expected, relative) = line
            .split_once("  ")
            .with_context(|| format!("invalid circuit hash line {}", index + 1))?;
        if relative.starts_with('/') || relative.split('/').any(|part| part == "..") {
            bail!("unsafe circuit hash path {relative}");
        }
        let actual = hex::encode(Sha256::digest(
            fs::read(root.join(relative))
                .with_context(|| format!("read circuit file {relative}"))?,
        ));
        if actual != expected.to_ascii_lowercase() {
            bail!("circuit SHA-256 mismatch for {relative}");
        }
    }
    Ok(())
}

pub struct SetupEngine {
    cpu: sp1_sdk::CpuProver,
    #[cfg(feature = "rocm")]
    rocm: sp1_sdk::RocmProver,
    #[cfg(feature = "rocm")]
    handles: Mutex<HashMap<Vec<u8>, sp1_rocm::RocmProvingKey>>,
    #[cfg(feature = "rocm")]
    rocm_child: Mutex<Option<Child>>,
}

impl SetupEngine {
    pub async fn new(config: &Config) -> Result<Arc<Self>> {
        let cpu = ProverClient::builder().cpu().build().await;
        #[cfg(not(feature = "rocm"))]
        let _ = config;
        #[cfg(feature = "rocm")]
        let rocm_child = start_rocm_server(config).await?;
        #[cfg(feature = "rocm")]
        let rocm = ProverClient::builder()
            .rocm()
            .with_device_id(0)
            .build()
            .await;
        Ok(Arc::new(Self {
            cpu,
            #[cfg(feature = "rocm")]
            rocm,
            #[cfg(feature = "rocm")]
            handles: Mutex::new(HashMap::new()),
            #[cfg(feature = "rocm")]
            rocm_child: Mutex::new(Some(rocm_child)),
        }))
    }
}

#[cfg(feature = "rocm")]
async fn start_rocm_server(config: &Config) -> Result<Child> {
    let log_path = std::env::var_os("SP1_ROCM_SERVER_LOG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| config.state_dir.join("sp1-rocm-server.log"));
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open ROCm server log {}", log_path.display()))?;
    let mut command = Command::new(&config.rocm_server);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .with_context(|| format!("start exact ROCm server {}", config.rocm_server.display()))?;

    let socket = std::path::Path::new("/tmp/sp1-rocm-0.sock");
    for _ in 0..300 {
        if UnixStream::connect(socket).await.is_ok() {
            return Ok(child);
        }
        if let Some(status) = child.try_wait().context("inspect ROCm server")? {
            anyhow::bail!("ROCm server exited during startup with {status}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
    anyhow::bail!("ROCm server did not create /tmp/sp1-rocm-0.sock within 30 seconds")
}

#[async_trait]
impl ProofEngine for SetupEngine {
    async fn derive_program(&self, elf: &[u8]) -> Result<DerivedProgram> {
        let pk = self
            .cpu
            .setup(Elf::from(elf))
            .await
            .context("derive SP1 program key")?;
        Ok(DerivedProgram {
            vk_hash: pk.verifying_key().hash_bytes().to_vec(),
            vk: bincode::serialize(pk.verifying_key()).context("serialize SP1 verifying key")?,
        })
    }

    async fn prove(
        &self,
        vk_hash: &[u8],
        elf: &[u8],
        stdin: SP1Stdin,
        mode: ProofMode,
    ) -> Result<Vec<u8>> {
        #[cfg(not(feature = "rocm"))]
        {
            let _ = (vk_hash, elf, stdin, mode);
            bail!("this binary was built without the rocm feature");
        }
        #[cfg(feature = "rocm")]
        {
            let pk = {
                let handles = self.handles.lock().await;
                handles.get(vk_hash).cloned()
            };
            let pk = match pk {
                Some(pk) => pk,
                None => {
                    let pk = self
                        .rocm
                        .setup(Elf::from(elf))
                        .await
                        .context("set up program in ROCm server")?;
                    if pk.verifying_key().hash_bytes().as_slice() != vk_hash {
                        bail!("ROCm setup returned a mismatched verifying key hash");
                    }
                    self.handles
                        .lock()
                        .await
                        .insert(vk_hash.to_vec(), pk.clone());
                    pk
                }
            };
            let request = self.rocm.prove(&pk, stdin);
            let proof = match mode {
                ProofMode::Core => request.core().await,
                ProofMode::Compressed => request.compressed().await,
                ProofMode::Plonk => request.plonk().await,
                ProofMode::Groth16 => request.groth16().await,
                ProofMode::UnspecifiedProofMode => bail!("proof mode is unspecified"),
            }
            .context("generate ROCm proof")?;
            self.rocm
                .verify(&proof, pk.verifying_key(), None)
                .context("verify generated proof locally")?;
            let network = ProofFromNetwork {
                proof: proof.proof,
                public_values: proof.public_values,
                sp1_version: proof.sp1_version,
            };
            bincode::serialize(&network).context("serialize ProofFromNetwork")
        }
    }

    async fn shutdown(&self) -> Result<()> {
        #[cfg(feature = "rocm")]
        {
            let Some(mut child) = self.rocm_child.lock().await.take() else {
                return Ok(());
            };
            if let Some(pid) = child.id() {
                let result = unsafe { libc::kill(pid as i32, libc::SIGINT) };
                if result != 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(error).context("send SIGINT to ROCm server");
                    }
                }
            }
            match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
                Ok(status) => {
                    status.context("wait for ROCm server")?;
                }
                Err(_) => {
                    child.start_kill().context("force ROCm server to stop")?;
                    child
                        .wait()
                        .await
                        .context("wait for forced ROCm server stop")?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsafe_hash_manifest_path() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("hashes");
        fs::write(&manifest, format!("{}  ../secret\n", "0".repeat(64))).unwrap();
        assert!(verify_hash_manifest(dir.path(), &manifest).is_err());
    }
}
