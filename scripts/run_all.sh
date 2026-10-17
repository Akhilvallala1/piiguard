#!/usr/bin/env bash
# Full pipeline, reproducible: baseline -> N generations -> report. Requires CRUSOE_API_KEY.
# Usage: scripts/run_all.sh [generations=6] [--llm]
set -euo pipefail
cd "$(dirname "$0")/.."
GENS="${1:-6}"; shift || true
PY=.venv/bin/python
test -n "${CRUSOE_API_KEY:-}" || { echo "CRUSOE_API_KEY not set"; exit 1; }

echo "== models on Crusoe (sanity) =="; $PY -m piiguard.cli models | grep -iE 'nemotron|deepseek' || true
echo "== generation 0 =="; $PY -m piiguard.cli eval --set heldout
git tag -f gen-0 >/dev/null
echo "== improving for $GENS generations =="; $PY -m piiguard.cli improve --generations "$GENS" "$@"
echo "== report =="; $PY -m piiguard.cli report
echo "== tags =="; git tag --list 'gen-*' | sort -V | tr '\n' ' '; echo
