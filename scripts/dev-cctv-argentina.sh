#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Argentina CCTV testing preset: curated Buenos Aires camera locations. Live
# GCBA frames additionally need CCTV_ARGENTINA_CLIENT_ID/SECRET (exported or
# in .env); startup, credentials, and LAN warnings belong to the normal
# launcher. Explicit environment overrides remain supported.
export CCTV_SOURCES_FILE="${CCTV_SOURCES_FILE:-config/cctv_sources.argentina.json}"
export CCTV_MAX_SOURCES="${CCTV_MAX_SOURCES:-48}"

exec bash "$ROOT_DIR/scripts/dev-fresh.sh"
