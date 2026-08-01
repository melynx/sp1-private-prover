#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <archive-directory> <destination>" >&2
  exit 2
fi
archive_dir=$1
destination=$2
staging=${destination}.staging.$$

(cd "$archive_dir" && sha256sum -c SHA256SUMS)
mkdir -p "$staging"
trap 'rm -rf "$staging"' EXIT INT TERM
mkdir -p "$staging/plonk/v6.1.0" "$staging/groth16/v6.1.0"
tar -xzf "$archive_dir/v6.1.0-plonk.tar.gz" -C "$staging/plonk/v6.1.0" --no-same-owner --no-same-permissions
tar --zstd -xf "$archive_dir/v6.1.0-groth16.extracted.tar.zst" -C "$staging/groth16/v6.1.0" --no-same-owner --no-same-permissions
(cd "$staging/plonk/v6.1.0" && sha256sum -c "$archive_dir/v6.1.0-plonk.extracted.sha256")
(cd "$staging/groth16/v6.1.0" && sha256sum -c "$archive_dir/v6.1.0-groth16.extracted.sha256")
sed 's|  |  plonk/v6.1.0/|' "$archive_dir/v6.1.0-plonk.extracted.sha256" > "$staging/SHA256SUMS.extracted"
sed 's|  |  groth16/v6.1.0/|' "$archive_dir/v6.1.0-groth16.extracted.sha256" >> "$staging/SHA256SUMS.extracted"
(cd "$staging" && sha256sum -c SHA256SUMS.extracted)
if [ -e "$destination" ]; then
  echo "$destination already exists; refusing to extract over it" >&2
  exit 1
fi
mv "$staging" "$destination"
trap - EXIT INT TERM
