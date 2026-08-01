use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use anyhow::{Context, Result};
use clap::Parser;
use sp1_private_prover::{
    config::{Args, Config},
    engine::{verify_runtime_assets, ProofEngine, SetupEngine, UnavailableEngine},
    http,
    proto::{
        artifact::artifact_store_server::ArtifactStoreServer,
        network::prover_network_server::ProverNetworkServer,
    },
    service::{Metrics, PrivateProverService},
    storage::{now, Storage},
};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    if args.healthcheck {
        return healthcheck(config.http_listen.port()).await;
    }
    std::env::set_var("SP1_ROCM_ALLOCATOR", "async");
    std::env::set_var("SP1_ROCM_SERVER", &config.rocm_server);
    std::env::set_var("SP1_PLONK_CIRCUIT_PATH", config.circuit_cache.join("plonk"));
    std::env::set_var(
        "SP1_GROTH16_CIRCUIT_PATH",
        config.circuit_cache.join("groth16"),
    );
    let assets = verify_runtime_assets(&config);
    let ready_at_start = assets.is_ok();
    let engine: Arc<dyn ProofEngine> = match assets {
        Ok(()) => SetupEngine::new(&config).await?,
        Err(error) => {
            error!(%error, "runtime assets are not ready");
            Arc::new(UnavailableEngine(error.to_string()))
        }
    };
    let storage = Storage::open(&config.state_dir)?;
    let service =
        PrivateProverService::new(config.clone(), storage, engine.clone(), Metrics::new()?);
    service.ready.store(ready_at_start, Ordering::Relaxed);
    if ready_at_start {
        tokio::spawn(service.clone().worker_loop());
    }
    tokio::spawn(maintenance(service.clone()));

    let http_router = http::router(service.clone());
    let mut grpc = Server::builder();
    if let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) {
        let identity =
            Identity::from_pem(tokio::fs::read(cert).await?, tokio::fs::read(key).await?);
        grpc = grpc.tls_config(ServerTlsConfig::new().identity(identity))?;
    }
    info!(grpc = %config.grpc_listen, http = %config.http_listen, "SP1 private prover service listening");
    let grpc_service = grpc
        .add_service(
            ArtifactStoreServer::new(service.clone()).max_decoding_message_size(1024 * 1024),
        )
        .add_service(ProverNetworkServer::new(service).max_decoding_message_size(16 * 1024 * 1024))
        .serve(config.grpc_listen);
    let http_service = serve_http(config.clone(), http_router);
    tokio::select! {
        result = http_service => result.context("HTTP server")?,
        result = grpc_service => result.context("gRPC server")?,
        result = shutdown_signal() => {
            result?;
            info!("shutdown signal received");
        },
    }
    engine.shutdown().await.context("shut down ROCm server")?;
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn serve_http(config: Config, router: axum::Router) -> Result<()> {
    if let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) {
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
        axum_server::bind_rustls(config.http_listen, tls)
            .serve(router.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(config.http_listen).await?;
        axum::serve(listener, router).await?;
    }
    Ok(())
}

async fn healthcheck(port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await??;
    stream
        .write_all(b"GET /health/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = [0_u8; 64];
    let read = stream.read(&mut response).await?;
    let line = std::str::from_utf8(&response[..read])?;
    if !line.starts_with("HTTP/1.1 204") {
        anyhow::bail!("readiness check failed");
    }
    Ok(())
}

async fn maintenance(service: PrivateProverService) {
    let mut ticks = 0_u64;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        ticks = ticks.wrapping_add(1);
        if ticks % 3_600 == 0 {
            let was_ready = service.ready.load(Ordering::Relaxed);
            service.ready.store(
                was_ready && verify_runtime_assets(&service.config).is_ok(),
                Ordering::Relaxed,
            );
        }
        if ticks % 60 == 0 {
            let _ = service.storage.cleanup(
                now(),
                now().saturating_sub(service.config.limits.terminal_retention.0),
            );
        }
        if let Some(path) = &service.config.gtt_path {
            match tokio::fs::read_to_string(path)
                .await
                .ok()
                .and_then(|value| value.trim().parse::<u64>().ok())
            {
                Some(bytes) if bytes > service.config.limits.gtt_guard_bytes => {
                    service.ready.store(false, Ordering::Relaxed);
                    error!(bytes, guard = service.config.limits.gtt_guard_bytes, "gfx1151 GTT guard exceeded; exiting so the container runtime terminates the ROCm child and restarts the service");
                    std::process::exit(70);
                }
                _ => {}
            }
        }
    }
}
