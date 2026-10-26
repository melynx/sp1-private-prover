use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use prometheus::{IntCounter, IntGauge, Registry};
use prost::Message;
use sha2::{Digest, Sha256};
use sp1_sdk::SP1Stdin;
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use crate::{
    auth::{recover_body_signer, recover_message_signer},
    config::Config,
    engine::ProofEngine,
    proto::{
        artifact::{
            artifact_store_server::ArtifactStore, ArtifactType, CreateArtifactRequest,
            CreateArtifactResponse,
        },
        network::{
            prover_network_server::ProverNetwork, CancelRequestRequest, CancelRequestResponse,
            CancelRequestResponseBody, CreateProgramRequest, CreateProgramResponse,
            CreateProgramResponseBody, ExecutionStatus, FulfillmentStatus, GetNonceRequest,
            GetNonceResponse, GetProgramRequest, GetProgramResponse, GetProofRequestParamsRequest,
            GetProofRequestParamsResponse, GetProofRequestStatusRequest,
            GetProofRequestStatusResponse, GetProversByUptimeRequest, GetProversByUptimeResponse,
            MessageFormat, Program, ProofMode, RequestProofRequest, RequestProofResponse,
            RequestProofResponseBody,
        },
    },
    storage::{now, JobState, Storage},
};

const LOCAL_ACTOR: [u8; 20] = [0x11; 20];
const CIRCUIT_VERSION: &str = "sp1-v6.1.0";

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    requests: IntCounter,
    failures: IntCounter,
    queued: IntGauge,
    active: IntGauge,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();
        let requests = IntCounter::new(
            "sp1_private_prover_requests_total",
            "Accepted proof requests",
        )?;
        let failures =
            IntCounter::new("sp1_private_prover_failures_total", "Failed proof requests")?;
        let queued = IntGauge::new("sp1_private_prover_queued_jobs", "Queued proof jobs")?;
        let active = IntGauge::new("sp1_private_prover_active_jobs", "Active GPU proof jobs")?;
        registry.register(Box::new(requests.clone()))?;
        registry.register(Box::new(failures.clone()))?;
        registry.register(Box::new(queued.clone()))?;
        registry.register(Box::new(active.clone()))?;
        Ok(Self {
            registry,
            requests,
            failures,
            queued,
            active,
        })
    }
}

#[derive(Clone)]
pub struct PrivateProverService {
    pub config: Arc<Config>,
    pub storage: Storage,
    pub engine: Arc<dyn ProofEngine>,
    pub metrics: Metrics,
    pub ready: Arc<AtomicBool>,
}

impl PrivateProverService {
    pub fn new(
        config: Config,
        storage: Storage,
        engine: Arc<dyn ProofEngine>,
        metrics: Metrics,
    ) -> Self {
        Self {
            config: Arc::new(config),
            storage,
            engine,
            metrics,
            ready: Arc::new(AtomicBool::new(true)),
        }
    }

    #[allow(clippy::result_large_err)] // tonic::Status is the required gRPC error type.
    fn authenticate<M: Message>(&self, body: &M, signature: &[u8]) -> Result<String, Status> {
        let signer = recover_body_signer(body, signature)?;
        if !self.config.signer_allowed(&signer) {
            return Err(Status::permission_denied("signer is not permitted"));
        }
        Ok(signer)
    }

    fn receipt(&self, operation: &[u8], signer: &str, body: &[u8]) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(b"sp1-private-prover-local-receipt-v1");
        digest.update(operation);
        digest.update(signer.as_bytes());
        digest.update(body);
        digest.finalize().to_vec()
    }

    pub async fn worker_loop(self) {
        loop {
            if let Err(error) = self.engine.check_health().await {
                error!(%error, "proof engine failed; restarting before claiming another job");
                std::process::exit(70);
            }
            match self.storage.next_job() {
                Ok(Some(job)) => {
                    self.metrics.queued.dec();
                    self.metrics.active.set(1);
                    let result = self.process_job(&job).await;
                    self.metrics.active.set(0);
                    if let Err(error) = result {
                        if let Err(health_error) = self.engine.check_health().await {
                            error!(%error, %health_error, "proof engine failed during a job; restarting so the running job is retried");
                            std::process::exit(70);
                        }
                        self.metrics.failures.inc();
                        error!(request_id = %hex::encode(&job.request_id), %error, "proof job failed");
                        if let Err(store_error) =
                            self.storage.fail(&job.request_id, &format!("{error:#}"))
                        {
                            error!(%store_error, "failed to persist proof failure");
                        }
                    }
                }
                Ok(None) => tokio::time::sleep(Duration::from_millis(200)).await,
                Err(error) => {
                    error!(%error, "failed to select queued proof job");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn process_job(&self, job: &crate::storage::Job) -> Result<()> {
        let program = self
            .storage
            .program(&job.request.vk_hash)?
            .context("program was removed")?;
        let elf_artifact = self
            .storage
            .artifact(&program.program_uri)?
            .context("program artifact was removed")?;
        let stdin_artifact = self
            .storage
            .artifact(&job.request.stdin_uri)?
            .context("stdin artifact was removed")?;
        let elf = tokio::fs::read(&elf_artifact.path).await?;
        let stdin_bytes = tokio::fs::read(&stdin_artifact.path).await?;
        let stdin: SP1Stdin = bincode::deserialize(&stdin_bytes).context("decode SP1Stdin")?;
        if !stdin.proofs.is_empty() {
            bail!("stdin with embedded proofs is not supported");
        }
        let mode = ProofMode::try_from(job.request.mode)
            .map_err(|_| anyhow::anyhow!("unknown proof mode {}", job.request.mode))?;
        let proof = self
            .engine
            .prove(&job.request.vk_hash, &elf, stdin, mode)
            .await?;
        if self
            .storage
            .job(&job.request_id)?
            .map(|current| current.state)
            == Some(JobState::Running)
        {
            self.storage.fulfill(
                &job.request_id,
                &proof,
                self.config.limits.proof_url_expiry.0,
                self.config.limits.retained_bytes,
            )?;
            info!(request_id = %hex::encode(&job.request_id), "proof job fulfilled and verified");
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl ArtifactStore for PrivateProverService {
    async fn create_artifact(
        &self,
        request: Request<CreateArtifactRequest>,
    ) -> Result<Response<CreateArtifactResponse>, Status> {
        let request = request.into_inner();
        let signer = recover_message_signer(b"create_artifact", &request.signature)?;
        if !self.config.signer_allowed(&signer) {
            return Err(Status::permission_denied("signer is not permitted"));
        }
        let kind = ArtifactType::try_from(request.artifact_type)
            .map_err(|_| Status::invalid_argument("artifact_type is invalid"))?;
        if !matches!(
            kind,
            ArtifactType::Program | ArtifactType::Stdin | ArtifactType::PrivateStdin
        ) {
            return Err(Status::invalid_argument("artifact_type is not accepted"));
        }
        let (uri, token) = self
            .storage
            .create_upload(
                &signer,
                request.artifact_type,
                self.config.limits.upload_expiry.0,
            )
            .map_err(internal)?;
        let upload = format!(
            "{}/upload/{token}",
            self.config.public_http_base.trim_end_matches('/')
        );
        Ok(Response::new(CreateArtifactResponse {
            artifact_uri: uri,
            artifact_presigned_url: upload,
        }))
    }
}

#[tonic::async_trait]
impl ProverNetwork for PrivateProverService {
    async fn get_nonce(
        &self,
        request: Request<GetNonceRequest>,
    ) -> Result<Response<GetNonceResponse>, Status> {
        let address = address_string(&request.into_inner().address)?;
        Ok(Response::new(GetNonceResponse {
            nonce: self.storage.nonce(&address).map_err(internal)?,
        }))
    }

    async fn get_program(
        &self,
        request: Request<GetProgramRequest>,
    ) -> Result<Response<GetProgramResponse>, Status> {
        let vk_hash = request.into_inner().vk_hash;
        if vk_hash.len() != 32 {
            return Err(Status::invalid_argument("vk_hash must contain 32 bytes"));
        }
        let program = self
            .storage
            .program(&vk_hash)
            .map_err(internal)?
            .ok_or_else(|| Status::not_found("program is not registered"))?;
        Ok(Response::new(GetProgramResponse {
            program: Some(program),
        }))
    }

    async fn create_program(
        &self,
        request: Request<CreateProgramRequest>,
    ) -> Result<Response<CreateProgramResponse>, Status> {
        let request = request.into_inner();
        if request.format != MessageFormat::Binary as i32 {
            return Err(Status::invalid_argument(
                "only binary message format is supported",
            ));
        }
        let body = request
            .body
            .ok_or_else(|| Status::invalid_argument("body is required"))?;
        let signer = self.authenticate(&body, &request.signature)?;
        let artifact = self
            .storage
            .artifact(&body.program_uri)
            .map_err(internal)?
            .ok_or_else(|| Status::failed_precondition("program artifact is not uploaded"))?;
        if artifact.kind != ArtifactType::Program as i32 || artifact.signer != signer {
            return Err(Status::permission_denied(
                "program artifact does not belong to signer",
            ));
        }
        let elf = tokio::fs::read(&artifact.path).await.map_err(internal)?;
        let derived = self
            .engine
            .derive_program(&elf)
            .await
            .map_err(failed_precondition)?;
        if body.vk_hash != derived.vk_hash || body.vk != derived.vk {
            return Err(Status::invalid_argument(
                "ELF, verifying key, or verifying key hash claim does not match setup",
            ));
        }
        if let Some(existing) = self.storage.program(&body.vk_hash).map_err(internal)? {
            if existing.vk == body.vk && existing.program_uri == body.program_uri {
                return Ok(Response::new(CreateProgramResponse {
                    tx_hash: self.receipt(b"create_program", &signer, &body.encode_to_vec()),
                    body: Some(CreateProgramResponseBody {}),
                }));
            }
            return Err(Status::already_exists(
                "verification key hash is registered with different data",
            ));
        }
        self.storage
            .consume_nonce(&signer, body.nonce)
            .map_err(failed_precondition)?;
        let program = Program {
            vk_hash: body.vk_hash.clone(),
            vk: body.vk.clone(),
            program_uri: body.program_uri.clone(),
            name: None,
            owner: decode_address(&signer).map_err(internal)?,
            created_at: now(),
        };
        self.storage.insert_program(&program).map_err(internal)?;
        Ok(Response::new(CreateProgramResponse {
            tx_hash: self.receipt(b"create_program", &signer, &body.encode_to_vec()),
            body: Some(CreateProgramResponseBody {}),
        }))
    }

    async fn get_proof_request_params(
        &self,
        request: Request<GetProofRequestParamsRequest>,
    ) -> Result<Response<GetProofRequestParamsResponse>, Status> {
        ProofMode::try_from(request.into_inner().mode)
            .map_err(|_| Status::invalid_argument("proof mode is invalid"))?;
        Ok(Response::new(GetProofRequestParamsResponse {
            domain: b"sp1-private-prover-v1".to_vec(),
            auctioneer: LOCAL_ACTOR.to_vec(),
            executor: LOCAL_ACTOR.to_vec(),
            verifier: LOCAL_ACTOR.to_vec(),
            max_price_per_pgu: "0".into(),
            base_fee: "0".into(),
            treasury: LOCAL_ACTOR.to_vec(),
            tick_size: 1,
        }))
    }

    async fn get_provers_by_uptime(
        &self,
        _request: Request<GetProversByUptimeRequest>,
    ) -> Result<Response<GetProversByUptimeResponse>, Status> {
        Ok(Response::new(GetProversByUptimeResponse {
            provers: vec![LOCAL_ACTOR.to_vec()],
        }))
    }

    async fn request_proof(
        &self,
        request: Request<RequestProofRequest>,
    ) -> Result<Response<RequestProofResponse>, Status> {
        let request = request.into_inner();
        if request.format != MessageFormat::Binary as i32 {
            return Err(Status::invalid_argument(
                "only binary message format is supported",
            ));
        }
        let body = request
            .body
            .ok_or_else(|| Status::invalid_argument("body is required"))?;
        let signer = self.authenticate(&body, &request.signature)?;
        validate_request(&self.config, &body)?;
        if self
            .storage
            .program(&body.vk_hash)
            .map_err(internal)?
            .is_none()
        {
            return Err(Status::failed_precondition("program is not registered"));
        }
        let stdin = self
            .storage
            .artifact(&body.stdin_uri)
            .map_err(internal)?
            .ok_or_else(|| Status::failed_precondition("stdin artifact is not uploaded"))?;
        if !matches!(stdin.kind, x if x == ArtifactType::Stdin as i32 || x == ArtifactType::PrivateStdin as i32)
            || stdin.signer != signer
        {
            return Err(Status::permission_denied(
                "stdin artifact does not belong to signer",
            ));
        }
        let request_id = deterministic_request_id(&signer, &body);
        if let Some(existing) = self.storage.job(&request_id).map_err(internal)? {
            if existing.signer == signer && existing.request == body {
                return Ok(Response::new(RequestProofResponse {
                    tx_hash: self.receipt(b"request_proof", &signer, &body.encode_to_vec()),
                    body: Some(RequestProofResponseBody { request_id }),
                }));
            }
        }
        let (global, queued, _active) = self.storage.queue_counts(&signer).map_err(internal)?;
        if global >= self.config.limits.queued_global {
            return Err(Status::resource_exhausted(
                "global queued job limit reached",
            ));
        }
        if queued >= self.config.limits.queued_per_signer {
            return Err(Status::resource_exhausted(
                "signer queued job limit reached",
            ));
        }
        self.storage
            .consume_nonce(&signer, body.nonce)
            .map_err(failed_precondition)?;
        if !self
            .storage
            .insert_job(&request_id, &signer, &body)
            .map_err(internal)?
        {
            return Err(Status::already_exists("request identifier collision"));
        }
        self.metrics.requests.inc();
        self.metrics.queued.inc();
        Ok(Response::new(RequestProofResponse {
            tx_hash: self.receipt(b"request_proof", &signer, &body.encode_to_vec()),
            body: Some(RequestProofResponseBody { request_id }),
        }))
    }

    async fn get_proof_request_status(
        &self,
        request: Request<GetProofRequestStatusRequest>,
    ) -> Result<Response<GetProofRequestStatusResponse>, Status> {
        let id = request.into_inner().request_id;
        let job = self
            .storage
            .job(&id)
            .map_err(internal)?
            .ok_or_else(|| Status::not_found("proof request is unknown"))?;
        let (fulfillment, execution) = network_status(job.state);
        let proof_uri = if job.state == JobState::Fulfilled {
            job.proof_token.as_ref().map(|token| {
                format!(
                    "{}/proof/{}/{}",
                    self.config.public_http_base.trim_end_matches('/'),
                    hex::encode(&id),
                    token
                )
            })
        } else {
            None
        };
        Ok(Response::new(GetProofRequestStatusResponse {
            fulfillment_status: fulfillment as i32,
            execution_status: execution as i32,
            request_tx_hash: self.receipt(
                b"request_proof",
                &job.signer,
                &job.request.encode_to_vec(),
            ),
            deadline: job.request.deadline,
            fulfill_tx_hash: (job.state == JobState::Fulfilled)
                .then(|| self.receipt(b"fulfill", &job.signer, &id)),
            proof_uri,
            public_values_hash: job.request.public_values_hash,
            proof_public_uri: None,
        }))
    }

    async fn cancel_request(
        &self,
        request: Request<CancelRequestRequest>,
    ) -> Result<Response<CancelRequestResponse>, Status> {
        let request = request.into_inner();
        if request.format != MessageFormat::Binary as i32 {
            return Err(Status::invalid_argument(
                "only binary message format is supported",
            ));
        }
        let body = request
            .body
            .ok_or_else(|| Status::invalid_argument("body is required"))?;
        let signer = self.authenticate(&body, &request.signature)?;
        if let Some(job) = self.storage.job(&body.request_id).map_err(internal)? {
            if job.signer != signer {
                return Err(Status::permission_denied(
                    "proof request belongs to another signer",
                ));
            }
        }
        self.storage
            .consume_nonce(&signer, body.nonce)
            .map_err(failed_precondition)?;
        self.storage
            .cancel(&body.request_id, &signer)
            .map_err(internal)?;
        Ok(Response::new(CancelRequestResponse {
            tx_hash: self.receipt(b"cancel", &signer, &body.encode_to_vec()),
            body: Some(CancelRequestResponseBody {}),
        }))
    }
}

#[allow(clippy::result_large_err)] // tonic::Status is the required gRPC error type.
fn validate_request(
    config: &Config,
    body: &crate::proto::network::RequestProofRequestBody,
) -> Result<(), Status> {
    if body.vk_hash.len() != 32 {
        return Err(Status::invalid_argument("vk_hash must contain 32 bytes"));
    }
    if body.version != CIRCUIT_VERSION {
        return Err(Status::invalid_argument("version must be sp1-v6.1.0"));
    }
    ProofMode::try_from(body.mode)
        .map_err(|_| Status::invalid_argument("proof mode is invalid"))?;
    if body.cycle_limit > config.limits.max_cycles {
        return Err(Status::invalid_argument(
            "cycle_limit exceeds configured maximum",
        ));
    }
    if body.gas_limit > config.limits.max_gas {
        return Err(Status::invalid_argument(
            "gas_limit exceeds configured maximum",
        ));
    }
    let current = now();
    if body.deadline <= current || body.deadline > current + config.limits.max_deadline.0 {
        return Err(Status::invalid_argument(
            "deadline must be in the future and at most four hours away",
        ));
    }
    if !body.stdin_uri.starts_with("sp1-private://artifact/") {
        return Err(Status::invalid_argument(
            "stdin_uri must identify a local uploaded artifact",
        ));
    }
    Ok(())
}

fn deterministic_request_id(signer: &str, body: &impl Message) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"sp1-private-prover-request-v1");
    digest.update(signer.as_bytes());
    digest.update(body.encode_to_vec());
    digest.finalize().to_vec()
}

fn network_status(state: JobState) -> (FulfillmentStatus, ExecutionStatus) {
    match state {
        JobState::Queued => (FulfillmentStatus::Requested, ExecutionStatus::Unexecuted),
        JobState::Running => (FulfillmentStatus::Assigned, ExecutionStatus::Unexecuted),
        JobState::Fulfilled => (FulfillmentStatus::Fulfilled, ExecutionStatus::Executed),
        JobState::Failed => (
            FulfillmentStatus::Unfulfillable,
            ExecutionStatus::Unexecutable,
        ),
        JobState::Canceled => (
            FulfillmentStatus::Unfulfillable,
            ExecutionStatus::Unexecuted,
        ),
    }
}

#[allow(clippy::result_large_err)] // tonic::Status is the required gRPC error type.
fn address_string(bytes: &[u8]) -> Result<String, Status> {
    if bytes.len() != 20 {
        return Err(Status::invalid_argument("address must contain 20 bytes"));
    }
    Ok(format!("0x{}", hex::encode(bytes)))
}
fn decode_address(value: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        value
            .strip_prefix("0x")
            .context("address lacks 0x prefix")?,
    )?)
}
fn internal(error: impl std::fmt::Display) -> Status {
    warn!(%error, "internal service operation failed");
    Status::internal("internal service operation failed")
}
fn failed_precondition(error: impl std::fmt::Display) -> Status {
    Status::failed_precondition(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_job_is_assigned_to_the_local_prover() {
        assert_eq!(
            network_status(JobState::Running),
            (FulfillmentStatus::Assigned, ExecutionStatus::Unexecuted)
        );
    }
}
