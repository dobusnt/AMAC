#!/usr/bin/env bash
set -euo pipefail

# Demo for Day 1–2: map from the sample OpenAPI and validate.
# Usage:
#   bash scripts/demo.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Ensure output dir exists
mkdir -p "$ROOT/out"

echo "[1/2] Mapping endpoints from examples/openapi.json..."
amac map \
  --openapi "$ROOT/examples/openapi.json" \
  --scope   "$ROOT/examples/scope.yml" \
  --out     "$ROOT/out/endpoints.json"

echo
echo "[2/2] Validating configs and endpoints..."
amac check \
  --endpoints "$ROOT/out/endpoints.json" \
  --scope     "$ROOT/examples/scope.yml" \
  --auth      "$ROOT/examples/auth.yml" \
  --preview

echo
echo "✅ Done. See $ROOT/out/endpoints.json"
