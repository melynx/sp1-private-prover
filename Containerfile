FROM docker.io/library/ubuntu:24.04

ARG SOURCE_COMMIT=uncommitted
LABEL org.opencontainers.image.title="sp1-private-prover" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="$SOURCE_COMMIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libdrm2 libgcc-s1 libnuma1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# dist/rocm must be copied from the exact ROCm 7.14 installation used to build
# sp1-rocm-server. No package manager or runtime download is used here.
COPY dist/rocm/ /opt/rocm/
COPY dist/sp1-private-prover /usr/local/bin/sp1-private-prover
COPY dist/sp1-rocm-server /usr/local/bin/sp1-rocm-server
COPY config.example.toml /etc/sp1-private-prover/config.toml

ENV LD_LIBRARY_PATH=/opt/rocm/core-7.14/lib:/opt/rocm/core-7.14/llvm/lib \
    SP1_ROCM_ALLOCATOR=async \
    RUST_LOG=info
USER 1000:1000
EXPOSE 50051 50052
VOLUME ["/var/lib/sp1-private-prover", "/var/cache/sp1/circuits"]
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["/usr/local/bin/sp1-private-prover", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/sp1-private-prover"]
CMD ["--config", "/etc/sp1-private-prover/config.toml"]
