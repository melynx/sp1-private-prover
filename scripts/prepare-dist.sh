#!/bin/sh
set -eu

expected_sp1_commit=f782d4ed34e5876589ae53538bd4ad68e416f031
expected_server_sha256=942ce14d2d7474ca58c081b0b46b404df1cff76398bb1c5077e6764af7acde72
server=vendor/sp1/target/release/sp1-rocm-server

actual_commit=$(git -C vendor/sp1 rev-parse HEAD)
if [ "$actual_commit" != "$expected_sp1_commit" ]; then
  echo "vendor/sp1 is $actual_commit; expected $expected_sp1_commit" >&2
  exit 1
fi

SP1_ROCM_ALLOCATOR=async cargo build --release --features rocm
if [ ! -x "$server" ]; then
  echo "$server is missing; build sp1-rocm-server in the pinned submodule first" >&2
  exit 1
fi
actual_server_sha256=$(sha256sum "$server" | cut -d' ' -f1)
if [ "$actual_server_sha256" != "$expected_server_sha256" ]; then
  echo "sp1-rocm-server SHA-256 is $actual_server_sha256; expected $expected_server_sha256" >&2
  exit 1
fi
if [ ! -d /opt/rocm ]; then
  echo "/opt/rocm is missing" >&2
  exit 1
fi

rm -rf dist
mkdir -p dist/rocm
cp target/release/sp1-private-prover dist/sp1-private-prover
cp "$server" dist/sp1-rocm-server
cp -a /opt/rocm/. dist/rocm/
sha256sum dist/sp1-private-prover dist/sp1-rocm-server > dist/SHA256SUMS
