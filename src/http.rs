use std::sync::atomic::{AtomicBool, Ordering};

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, put},
    Router,
};
use prometheus::{Encoder, TextEncoder};

use crate::{engine::ProofEngine, service::PrivateProverService};

pub fn router(service: PrivateProverService) -> Router {
    let maximum = service.config.limits.max_artifact_compressed_bytes as usize;
    Router::new()
        .route("/upload/:token", put(upload))
        .route("/proof/:request_id/:token", get(proof))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(maximum))
        .with_state(service)
}

async fn upload(
    State(service): State<PrivateProverService>,
    Path(token): Path<String>,
    body: Bytes,
) -> Response {
    if body.len() as u64 > service.config.limits.max_artifact_compressed_bytes {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "compressed artifact exceeds configured limit",
        )
            .into_response();
    }
    match service.storage.store_upload(
        &token,
        &body,
        service.config.limits.max_artifact_expanded_bytes,
        service.config.limits.max_elf_bytes,
        service.config.limits.retained_bytes,
    ) {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(error)
            if error.to_string().contains("expired") || error.to_string().contains("unknown") =>
        {
            (StatusCode::GONE, "upload URL is expired or already used").into_response()
        }
        Err(error) if error.to_string().contains("exceeds") => {
            (StatusCode::PAYLOAD_TOO_LARGE, error.to_string()).into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, "artifact upload is invalid").into_response(),
    }
}

async fn proof(
    State(service): State<PrivateProverService>,
    Path((request_id, token)): Path<(String, String)>,
) -> Response {
    let Ok(id) = hex::decode(request_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match service.storage.proof(&id, &token) {
        Ok(Some(bytes)) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            bytes,
        )
            .into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn live() -> StatusCode {
    StatusCode::NO_CONTENT
}
async fn ready(State(service): State<PrivateProverService>) -> StatusCode {
    readiness_status(&service.ready, service.engine.as_ref()).await
}

async fn readiness_status(ready: &AtomicBool, engine: &dyn ProofEngine) -> StatusCode {
    if !ready.load(Ordering::Relaxed) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    if let Err(error) = engine.check_health().await {
        ready.store(false, Ordering::Relaxed);
        tracing::error!(%error, "proof engine is unavailable");
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::NO_CONTENT
}
async fn metrics(State(service): State<PrivateProverService>) -> Response {
    let encoder = TextEncoder::new();
    let mut output = Vec::new();
    if encoder
        .encode(&service.metrics.registry.gather(), &mut output)
        .is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    ([(header::CONTENT_TYPE, encoder.format_type())], output).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::UnavailableEngine;

    #[tokio::test]
    async fn readiness_fails_when_engine_is_unavailable() {
        let ready = AtomicBool::new(true);
        let engine = UnavailableEngine("worker exited".to_string());
        assert_eq!(
            readiness_status(&ready, &engine).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(!ready.load(Ordering::Relaxed));
    }
}
