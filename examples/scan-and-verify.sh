#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 PROJECT_ROOT [STATE_DIR]" >&2
  exit 64
fi

project_root=$1
state_dir=${2:-"$HOME/.local/state/osv-threat-delta/$(basename "$project_root")"}

osv-threat-delta scan \
  --root "$project_root" \
  --lock requirements.lock \
  --state-dir "$state_dir" \
  --format summary

osv-threat-delta verify \
  --root "$project_root" \
  --lock requirements.lock \
  --state-dir "$state_dir" \
  --format summary
