#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <state-dir> <circuit-dir> <config-file> <quadlet-output>" >&2
  exit 2
fi

pci_device=/sys/bus/pci/devices/0000:c5:00.0
drm_dir=$pci_device/drm
render_node=
for candidate in "$drm_dir"/renderD*; do
  if [ -e "$candidate" ]; then
    render_node=/dev/dri/$(basename "$candidate")
    break
  fi
done
if [ -z "$render_node" ] || [ ! -c "$render_node" ]; then
  echo "no render node found for PCI device 0000:c5:00.0" >&2
  exit 1
fi

state_dir=$1
circuit_dir=$2
config_file=$3
output=$4
additional_render_devices=
for candidate in /dev/dri/renderD*; do
  if [ -c "$candidate" ] && [ "$candidate" != "$render_node" ]; then
    additional_render_devices="${additional_render_devices}AddDevice=${candidate}
"
  fi
done

sed \
  -e "s|@RENDER_NODE@|$render_node|g" \
  -e "s|@STATE_DIR@|$state_dir|g" \
  -e "s|@CIRCUIT_DIR@|$circuit_dir|g" \
  -e "s|@CONFIG_FILE@|$config_file|g" \
  deploy/sp1-private-prover.container.in |
  awk -v devices="$additional_render_devices" '
    $0 == "@ADDITIONAL_RENDER_DEVICES@" { printf "%s", devices; next }
    { print }
  ' > "$output"
echo "wrote $output with $render_node selected for PCI device 0000:c5:00.0"
