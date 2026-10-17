# piiguard: a PII leak guard that hardens itself

**Recursive Agents Hackathon, San Francisco, 2026-10-17. Theme: Version N+1.**

Sandboxes like NVIDIA NemoClaw / OpenShell decide *where* an agent may send bytes.
They do not look at *what* is in the bytes. An agent with a perfectly reasonable egress policy
(Crusoe for inference, You.com for search) will happily paste a customer's SSN into a search query,
and the sandbox will allow it, because the host is on the allow-list.

piiguard is the missing content layer, and it is built to get better on its own:

1. **Guard proxy** sits between the sandboxed agent and every allowed egress. It redacts PII in outbound
   payloads to reversible tokens (`[PII_SSN_1]`), forwards the request, and restores the values on the way
   back so the agent still completes its task. Provider keys live in the proxy, never in the sandbox.
2. **Red team** (Nemotron 3 Super on Crusoe + deterministic encoders) generates attacks that smuggle PII past
   the guard: base64, hex, spaced digits, fullwidth unicode, spelled-out numbers, percent-encoding, ROT18,
   reversed strings, non-breaking separators, split across lines, inside JSON / URLs / code / logs / tables.
3. **Coach** (Nemotron 3 Super) reads the attacks that leaked and rewrites the guard's two evolvable artifacts:
   `guard/rules.yaml` (regex rules) and `guard/prompt.md` (instructions for a small Nemotron 3.5 Lightning
   span classifier).
4. **Gate** keeps a change only if the leak rate on a *validation* set drops and false positives on clean
   traffic do not rise. Accepted changes are committed and tagged `gen-N`; rejected ones are reverted and logged.
5. **Score** is the leak rate on a *held-out* attack set the coach never sees, generation 0 versus generation N.

Everything in this repository was written during the event. The design is informed by an earlier,
unrelated guardrail project by the same author, but no code was reused.

## Results

Generation 0 (hand-written baseline rules, no LLM classifier), 150 attacks, 60/20/20 split:

| set | leak rate | false positives (25 hard negatives) |
|---|---|---|
| held-out | 76.7 % (23/30) | 0.0 % |

Run `piiguard report` after `piiguard improve` for the before/after table. Results from the live run are
appended below before submission.

## Quickstart

```bash
uv venv --python 3.12 && uv pip install -e ".[dev]"
export CRUSOE_API_KEY='...'   # quote it, keys may contain $
export YDC_API_KEY='...'

piiguard models                              # confirm model ids on Crusoe
piiguard gen-attacks --n 150 --seed 42       # data/attacks/{train,val,heldout}.jsonl
piiguard eval --set heldout --show-misses    # generation 0 score
piiguard improve --generations 6 --llm       # coach + gate loop, commits gen-N tags
piiguard report                              # history + held-out before/after
```

Live demo pieces:

```bash
piiguard serve --port 8787 --llm             # the guard proxy (holds the Crusoe + You.com keys)
python scripts/demo_leak.py --live           # same request direct vs guarded
bash nemoclaw/onboard.sh                     # NemoClaw sandbox whose only egress is the guard
```

## Layout

```
guard/rules.yaml, guard/prompt.md   evolvable guard artifacts (git-tagged per generation)
piiguard/pii/                        rules, regex+LLM guard, reversible redaction
piiguard/redteam/                    encoders + attack generator (+ optional LLM carriers)
piiguard/eval/                       harness, scoring, hard-negative clean set
piiguard/coach/                      retrospective (coach prompt + parsing), gate (decide, git)
piiguard/loop.py                     one generation: eval -> coach -> stage -> gate -> commit/revert
piiguard/proxy.py                    FastAPI guard proxy: /v1/chat/completions, /you/search, /events
nemoclaw/                            onboard script + egress policy presets (leaky vs guarded)
scripts/demo_leak.py                 the hook
runs/                                history.jsonl, report.json, proxy-events.jsonl
```

## Stack

- **Crusoe Managed Inference** for all models (OpenAI-compatible endpoint).
- **NVIDIA Nemotron**: 3.5 Lightning 30B-A3B as the span classifier and demo agent model, 3 Super 120B-A12B as coach and red team.
- **NVIDIA NemoClaw / OpenShell** as the sandbox; the guard is pitched as its content layer and is the sandbox's only inference route.
- **You.com** search as the second egress the guard protects (and the exfil channel in the demo).

## Safety notes

- The coach is an LLM writing regexes. Every proposed pattern is length-capped, rejected if it has nested
  quantifiers, and timed against a probe string before it is accepted (ReDoS guard).
- Overlapping findings are merged into their union span so no partial value survives redaction.
- All seed PII is synthetic: never-issued 9xx SSNs, 555-01xx phones, public card test numbers, example.com emails.
