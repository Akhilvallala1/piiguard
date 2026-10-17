#!/usr/bin/env bash
# One-shot sequence for the 1-minute video / 3-minute live demo. Run from repo root with the proxy up:
#   export GUARD_PROXY_TOKEN=...; piiguard serve --host 0.0.0.0 --port 8787 --llm   (terminal 1)
#   bash scripts/demo_record.sh                                                     (terminal 2)
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.nvm/versions/node/v22.23.3/bin:/opt/homebrew/bin:$PATH"
set -a; . ./.env; set +a
PY=.venv/bin/python
pause() { echo; read -r -p "--- [enter] $1 " _; echo; }

clear
echo "piiguard: a PII leak guard that hardens itself"
pause "1/5 the hook: same agent request, direct vs guarded"
$PY scripts/demo_leak.py --live

pause "2/5 from inside the NemoClaw sandbox (its only route is the guard)"
nemoclaw piiguard-agent status 2>/dev/null | grep -E "Provider|Inference:" | head -2
nemoclaw piiguard-agent exec -- sh -c 'curl -sk -m 60 https://inference.local/v1/chat/completions -H "Content-Type: application/json" -d "{\"model\":\"nvidia/Nemotron-3.5-Lightning-30B-A3B\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply OK. Customer SSN 912-34-5678, email maria.chen@example.com\"}],\"max_tokens\":300}" >/dev/null; echo sent from sandbox' 2>/dev/null | grep -v Warning
echo "what left the host:"; tail -1 runs/proxy-events.jsonl | $PY -c "import sys,json; print('  ', json.load(sys.stdin)['preview'])"

pause "3/5 generation 0 vs generation N (held-out, coach never saw it)"
$PY -m piiguard.cli report

pause "4/5 what the system learned (plain YAML diff) + one rejected idea"
git --no-pager diff gen-0 "$(git tag --list 'gen-*' | sort -V | tail -1)" --stat -- guard/
git --no-pager diff gen-0 "$(git tag --list 'gen-*' | sort -V | tail -1)" -- guard/rules.yaml | grep -E "^\+.*name:" | head -12
echo; echo "rejected proposals and why:"; $PY -c "
import json
for l in open('runs/history.jsonl'):
    r=json.loads(l)
    if not r['accepted']: print(f\"  gen {r['gen']}: {r['reason'][:90]}\")
" | head -6

pause "5/5 same data, other systems"
$PY -m piiguard.cli bench --set heldout --llm 2>/dev/null | head -8
echo; echo "done."
