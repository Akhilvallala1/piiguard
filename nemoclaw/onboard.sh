#!/usr/bin/env bash
# Onboard a NemoClaw (OpenShell) sandbox whose ONLY inference route is the PII guard proxy on the host.
# The agent inside the sandbox never holds the Crusoe key; the guard proxy holds it and redacts outbound traffic.
#
# Prereqs: Docker Desktop running; `nemoclaw` CLI installed (curl -fsSL https://www.nvidia.com/nemoclaw.sh | bash);
#          the guard proxy running on the host:  piiguard serve --port 8787
set -euo pipefail
: "${GUARD_PROXY_TOKEN:=guard-dev-token}"
: "${SANDBOX_NAME:=piiguard-agent}"
: "${NEMOCLAW_MODEL:=nvidia/nemotron-3.5-lightning-30b-a3b}"
# host.openshell.internal is how a sandbox reaches services on the host through the OpenShell gateway.
: "${GUARD_URL:=http://host.openshell.internal:8787/v1}"

echo "Onboarding sandbox '$SANDBOX_NAME' -> guard proxy at $GUARD_URL (model $NEMOCLAW_MODEL)"
NEMOCLAW_NON_INTERACTIVE=1 \
NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1 \
NEMOCLAW_AGENT="${NEMOCLAW_AGENT:-openclaw}" \
NEMOCLAW_PROVIDER=custom \
NEMOCLAW_ENDPOINT_URL="$GUARD_URL" \
NEMOCLAW_MODEL="$NEMOCLAW_MODEL" \
NEMOCLAW_SANDBOX_NAME="$SANDBOX_NAME" \
COMPATIBLE_API_KEY="$GUARD_PROXY_TOKEN" \
nemoclaw onboard --non-interactive

echo "Applying egress policy preset (guard proxy + You.com via guard only)"
nemoclaw "$SANDBOX_NAME" policy add --from-file "$(dirname "$0")/piiguard-egress.yaml" --yes
nemoclaw "$SANDBOX_NAME" policy list
nemoclaw "$SANDBOX_NAME" status
