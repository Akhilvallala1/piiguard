# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`piiguard` is a self-hardening PII leak guard for sandboxed AI agents, built for The Recursive Agents Hackathon (2026-10-17, submissions due 5 PM PT, 1-minute demo video + public repo required). Theme: **Version N+1** — a self-improving system that must show a measurable before/after score. All inference runs on Crusoe Managed Inference (OpenAI-compatible, `CRUSOE_BASE_URL`). Side-prize targets: Best Use of NemoClaw/OpenShell and Best Use of Nemotron.

Hackathon rules that constrain design: no dashboards as the main feature, no basic RAG, no Streamlit, and only new work (the user's prior AgentShield / Conduit projects cannot be reused).

## Commands

```bash
# one-time setup (the .venv exists but is empty until this runs)
.venv/bin/python -m pip install -e ".[dev]"
cp .env.example .env   # fill in CRUSOE_API_KEY, YDC_API_KEY; keep keys single-quoted (they may contain $)

# tests
.venv/bin/python -m pytest                       # all
.venv/bin/python -m pytest tests/test_guard.py   # one file
.venv/bin/python -m pytest tests/test_gate.py::test_rejects_when_leak_does_not_drop_enough  # one test

# CLI entry point (pyproject declares `piiguard = piiguard.cli:main`)
.venv/bin/piiguard models                        # list Crusoe models to confirm WORKER_MODEL / COACH_MODEL ids
```

Python >= 3.11 (venv is 3.12). Build backend is hatchling; `pytest` is the only dev dep.

## Current state

The repo was built test-first. `tests/` fully specifies the public API of the core modules; the `piiguard/` package currently contains only empty `__init__.py` files, and `guard/`, `data/attacks/`, `data/clean/`, `nemoclaw/`, `scripts/` are empty directories. When implementing, make the existing tests pass without editing them unless the test itself is wrong.

## Architecture

The system is a closed loop: **red team → guard → eval → coach → gate → commit**, repeated. Each iteration should lower leak rate without raising false-positive rate, and the git history of `guard/` is the before/after evidence for the demo.

### Guard (`piiguard/pii/`) — the artifact being improved
- `guard/rules.yaml` + `guard/prompt.md` are the **mutable guard definition**. They are data, versioned in git, and the only thing the coach is allowed to change.
- `rules.py`: `load_rules(path) -> RuleSet` with `.rules`, each rule having `.name`, `.regex` (compiled), and `.validate(text)`. Rules may carry a validator; `credit_card` uses `luhn_ok`. Shipped rule names must include at least `ssn`, `email`, `phone_us`, `credit_card`.
- `guard.py`: `Guard.from_dir(guard_dir)`; `guard.redact(text)` returns an object with `.text`, `.mapping`, `.findings`. Redaction replaces each distinct value with a **typed, numbered token** like `[PII_SSN_1]` / `[PII_EMAIL_1]` / `[PII_PHONE_US_1]` (token type = uppercased rule name). The same value seen twice maps to the same token. `guard.restore(text, mapping)` must round-trip exactly. Clean text passes through byte-identical with `findings == []`.

### Red team (`piiguard/redteam/`) — generates attacks
- `encoders.py`: `ENCODERS` registry and `encode(name, value)`. Baseline techniques: `plain, base64, spaced_digits, fullwidth, hex, spelled, split_lines, url_param, rot13`. Each encoder produces a *surface form* of the secret; `is_leak` checks for these surface forms, so an encoder must emit something that can be searched for literally in output.
- Attack datasets live in `data/attacks/` and clean (no-PII) controls in `data/clean/`. Plan: split into train / val / heldout so the coach only ever sees train, and the reported score is on heldout.

### Eval (`piiguard/eval/`) — scoring
- `scoring.py`: `is_leak(output, surface_forms)` (any surface form surviving = leak), `score_attacks(results)` → `{"leak_rate", "by_technique": {technique: rate}}`, `score_clean(results)` → `{"fp_rate"}` where a clean sample with `redactions > 0` counts as a false positive.

### Coach + gate (`piiguard/coach/`) — the self-improvement step
- `retrospective.py`: asks the `COACH_MODEL` for a patch and parses it with `parse_proposal(text)`. The proposal is JSON (optionally wrapped in a ```` ```json ```` fence) with `rationale`, `rules_yaml`, `prompt_md`. Parsing **compiles** `rules_yaml` through `load_rules`; invalid regex or non-JSON raises `ProposalError`. Never apply a proposal that did not parse.
- `gate.py`: `decide(before, after, min_leak_delta, max_fp_increase)` → object with `.accepted` and `.reason`. Accept only if leak rate drops by at least `min_leak_delta` **and** fp rate rises by no more than `max_fp_increase`; `reason` mentions "leak" on accept and "false positive" when rejected for FP regression. The loop commits/tags `guard/` on accept and reverts on reject.

### Models (from `.env.example`)
- `WORKER_MODEL` (Nemotron 3.5 Lightning 30B) sits behind the guard and handles agent traffic.
- `COACH_MODEL` (Nemotron 3 Super 120B) proposes guard patches.
- `FALLBACK_MODEL` (DeepSeek V4 Flash) if a Nemotron model is unavailable. Confirm ids against `/v1/models`; Crusoe availability varies by account.

### Planned, not yet scaffolded
- **Proxy**: FastAPI/uvicorn OpenAI-compatible endpoint (and You.com pass-through via `YDC_API_KEY`) that redacts outbound requests and restores inbound responses; authenticated with `GUARD_PROXY_TOKEN`. This is what a NemoClaw sandbox points at.
- **`nemoclaw/`**: onboard script, OpenShell egress policy YAML (allow only the proxy, deny direct Crusoe/You.com reach), and a leak-demo script.
- **`runs/`**: per-iteration JSONL logs (gitignored except `.gitkeep`).

## Conventions

- Keep the guard definition in `guard/` as plain YAML/Markdown so the coach's diff is human-readable and git-diffable; do not move detection logic into Python that the coach cannot edit.
- Secrets in `.env` only; `.env.example` is the documented schema.
