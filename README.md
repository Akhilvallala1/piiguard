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

## A worked example: an insurance claims assistant

An insurer deploys an agent that helps adjusters close claims. It runs inside a NemoClaw sandbox because the
security team insists on isolation. The policy allows two hosts: Crusoe for the model, You.com to look up repair
shops. Everything else is blocked.

An adjuster types: *"Claim CLM-2026-0048213, adjuster badge ADJ-48213-TX, policy POL 88-4421-7730 for Maria Chen,
callback 555-010-1234. Find three body shops near her and draft the approval."*

**Without piiguard.** The agent builds a web search: `body shops near Maria Chen 555-010-1234 claim CLM-2026-0048213`.
OpenShell checks the host. You.com is allowed. The query leaves. A customer name, a phone number and a claim number
are now in a third-party search log. Then the agent sends the whole ticket to the model endpoint. Also allowed.
Every value leaves again. The policy worked exactly as written. Nobody broke a rule. The data still left.

**With piiguard.** The sandbox's only route is the proxy on the host. The search query that leaves is
`body shops near [PII_NAME_1] [PII_PHONE_US_1] claim [PII_CLAIM_NUMBER_1]`. The model prompt that leaves has tokens
where the badge, claim, policy, name and phone were. The model drafts the approval around the tokens. On the way
back, piiguard swaps the real values in, so the adjuster sees "Approval for Maria Chen, claim CLM-2026-0048213" and
the agent finished its job. The egress log on the host shows exactly what left: five tokens, zero values.

**Why it had to learn.** On day one nobody at the insurer wrote a rule for adjuster badges. The insurance pack's red
team generated attacks with badges hidden in logs, URLs and spelled-out digits; the coach wrote the rules; the gate
kept the ones that worked (`gen-22`, `gen-23`: insurance held-out leak 90% → 20%). When a new claim-number format
appears, the red team picks it up from the pack, the coach adapts, held-out stays honest, and the security reviewer
reads a git diff of two regex lines, not a model.

**Why Presidio alone would not have done it.** Run the same ticket through Presidio and the phone and the name are
caught, the policy number is mislabeled as a phone, and the badge and claim number pass through untouched. It has
no recognizer for them and no way to grow one. The demo page shows all of this on the "Insurance claim" preset.

Swap the nouns and it is the same story for a hospital's discharge-note agent with record numbers, a bank's wire
desk with routing numbers, or a law firm's paralegal agent with docket numbers. Those four are the presets.

## Results

All numbers below are produced by the code in this repo during the event and injected by
`scripts/update_readme.py`. Held-out attacks are never shown to the coach. False positives are measured on
25 number-heavy clean samples (timestamps, versions, order ids, prices, coordinates).

### Same data, different systems

<!-- bench:start -->
| system | held-out leak rate | false positives | ms/text |
|---|---|---|---|
| NemoClaw sandbox policy only (no content layer) | 100.0% (30/30) | 0.0% | 0 |
| Microsoft Presidio (default recognizers) | 53.3% (16/30) | 64.0% | 5 |
| Microsoft Presidio (scoped: SSN, email, phone, card) | 70.0% (21/30) | 4.0% | 3 |
| piiguard gen-0 (hand-written rules) | 76.7% (23/30) | 0.0% | 0 |
| piiguard gen-14 rules (self-improved, no model call) | 16.7% (5/30) | 0.0% | 1 |
| piiguard gen-14 rules + Nemotron 3.5 Lightning classifier | 0.0% (0/30) | 0.0% | 2899 |
<!-- bench:end -->

Presidio's default recognizers also flag dates, places and names, which is why its false-positive rate on
clean agent traffic is high; the scoped row limits it to the same entity types piiguard targets. The point
is not that Presidio is weak. It is that a static detector stays where it is, and piiguard closes the gap on
its own, on attacks its coach never saw.

Two layers, two jobs. The **rules** are the cheap path: microseconds per request, no tokens, and they are what
the coach evolves. The **Nemotron 3.5 Lightning classifier** is the expensive safety net behind them (about a
second and a model call per request). Read the table as: how far can the free layer get on its own, and what
does the paid layer add. Over time the coach moves the free layer toward what the paid layer catches, which is
the whole point of the loop.

### External check: NVIDIA Nemotron-PII (data we did not make)

Everything above is scored on attacks our own red team generated. To answer "you wrote the test", we also ran the
same systems on a stratified sample of NVIDIA's public
[Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) test split (CC-BY-4.0): real-looking documents
across 29 domains with human-readable span labels. A span counts as caught if neither it nor its alphanumeric core
survives redaction. `scripts/eval_external.py` reproduces it.

<!-- external:start -->
| system | all labels, entity recall | structured identifiers, recall | records with any leak | ms/text |
|---|---|---|---|---|
| Microsoft Presidio (default) | 65.9% | 68.5% | 88.6% | 16 |
| piiguard gen-0 rules | 12.0% | 43.5% | 100.0% | 0 |
| piiguard current rules | 15.6% | 43.5% | 100.0% | 4 |
| piiguard current rules + matching industry pack | 15.6% | 43.5% | 100.0% | 5 |
| piiguard rules + industry pack + Nemotron classifier (routed) | 58.3% | 92.8% | 84.5% | 554 |

290 records, 2630 labeled spans, 29 domains, locale us, seed 7. Structured identifiers: 597 spans (account_number, api_key, bank_routing_number, certificate_license_number, credit_debit_card, customer_id, cvv, date_of_birth, device_identifier, email, employee_id, license_plate…).
<!-- external:end -->

Read this table honestly. Nemotron-PII labels semantic PII too: first and last names, cities, counties, countries,
companies, URLs, times. Presidio's named-entity models cover those and our regex-first design was never aimed at them,
so on all labels Presidio leads. On structured identifiers, the thing a learnable rule layer is for, the picture flips,
and the classifier closes most of the semantic gap at about a second per request. The leak rate on our adversarial sets
and the recall on this dataset are different questions; the second one is the one we did not get to choose.

### Generation history (what the coach proposed, what the gate decided)

<!-- generations:start -->
| gen | kept | val leak before → after | false positives before → after | commit | coach rationale |
|---|---|---|---|---|---|
| 1 | yes | 70% → 50% | 0% → 0% | 9af5466 | Add rules that catch the encoded and obfuscated forms seen in the leaks (spaced digits, reversed groups, spell |
| 2 | no | 50% → 0% | 0% → 100% | — | Add detection for Base64 and hex-encoded PII (the largest remaining leak sources) and relax the SSN, DOB, and  *(rejected)* |
| 3 | yes | 50% → 33% | 0% → 0% | a48d0e8 | Add context‑specific detectors for Base64 and hex‑encoded PII that only trigger after known field names (ssn,  |
| 4 | no | 33% → 33% | 0% → 0% | — |  *(rejected)* |
| 5 | no | 33% → 30% | 0% → 0% | — | Add generic detectors for hex‑ and base64‑encoded PII that rely on structural properties of the encoding (hex  *(rejected)* |
| 6 | no | 33% → 33% | 0% → 0% | — |  *(rejected)* |
| 7 | no | 33% → 33% | 0% → 0% | — |  *(rejected)* |
| 8 | no | 33% → 33% | 0% → 0% | — |  *(rejected)* |
| 9 | no | 33% → 40% | 0% → 0% | — | Add generic detectors for Base64- and hex-encoded PII that decode and validate against plain rules, plus a gen *(rejected)* |
| 10 | no | 33% → 10% | 0% → 8% | — | Add generic detectors that rely on validators to catch encoded or obfuscated PII without relying on label pref *(rejected)* |
| 11 | no | 33% → 37% | 0% → 8% | — | Add broad-but-validated detectors for Base64 and hex encoded PII, reversed digit sequences, normalized separat *(rejected)* |
| 12 | no | 33% → 33% | 0% → 0% | — |  *(rejected)* |
| 13 | no | 33% → 33% | 0% → 0% | — |  *(rejected)* |
| 14 | yes | 33% → 17% | 0% → 0% | bfd0300 | Add broad-but-validated detectors for base64, hex, and reversed encoded PII that decode and validate against p |
| 15 | no | 0% → 0% | 0% → 0% | — | Add detection for hex-encoded PII that may be prefixed with '0x' to catch obfuscated hex strings currently mis *(rejected)* |
| 17 | no | 60% → 60% | 0% → 0% | — |  *(rejected)* |
| 18 | no | 60% → 55% | 0% → 8% | — | Add a generic reversed-PII rule that catches reversed claim numbers and adjuster badges (e.g., '2150980-5202-M *(rejected)* |
| 19 | no | 60% → 40% | 0% → 8% | — | The biggest remaining leak is hex-encoded PII (1.00 leak rate), especially adjuster badges like '41444a2d34383 *(rejected)* |
| 20 | no | 60% → 55% | 0% → 0% | — | Adding plain-text rules for adjuster badge and claim number lets the existing generic base64, hex, reversed, a *(rejected)* |
| 21 | no | 60% → 85% | 0% → 0% | — | Add plain-text rules for adjuster badge, claim number, and policy number so that hex-, base64-, and reversed-e *(rejected)* |
| 22 | yes | 60% → 45% | 0% → 0% | 4249442 | Add precise plain-text rules for adjuster badge, claim number, and policy number so that existing base64, hex, |
| 23 | yes | 45% → 35% | 0% → 0% | c04e6d9 | The largest remaining leak classes are split_lines (0.83) and reversed (0.80), plus rot13 (0.70) which decodes |

**Held-out attacks (never shown to the coach, n=30): leak rate 76.7% → 16.7%. False positives on clean traffic: 0.0% → 0.0%.**
<!-- generations:end -->

Every accepted generation is a git tag (`git tag --list 'gen-*'`); `git diff gen-0 gen-14 -- guard/` shows
exactly what the system learned, in plain YAML.

### Industry-specific PII: the insurance pack

What counts as PII depends on the industry. An adjuster badge number is noise to a generic detector and a key to a
claim file inside an insurer. `piiguard gen-attacks --domain insurance` builds a red team that speaks insurance
(adjuster badges, claim numbers, policy numbers, plus SSNs and phones) and the same loop runs on it:

<!-- insurance:start -->
| set | gen-0 rules | current rules |
|---|---|---|
| insurance held-out leak rate (n=20) | 90.0% | 20.0% |
| false positives on clean traffic | 0.0% | 0.0% |
<!-- insurance:end -->

Presidio on the same prompts catches the phone and the name and walks past the badge and the claim. The demo page
has an "Insurance claim" preset that shows all four panes on it.

### Unlearning, with a tripwire

`piiguard prune --gen N` is the forgetting half of the loop: it removes each rule in turn and keeps the removal
only if the leak rate on train+val and the false-positive rate on clean traffic are both unchanged. Held-out is
never used to decide, but it is checked as a tripwire before anything is committed. On this dataset the step
found 10 rules that looked dead on 120 attacks, and the tripwire showed that removing them raised held-out leak
from 16.7 % to 26.7 %, so it refused to commit. That is the right answer: with 150 attacks, "never fired on what
I can measure" is not the same as "useless", and a guard should forget only when forgetting is provably free.
Rollback is always one command: every generation is a tag, so `git checkout gen-3 -- guard/` undoes anything.

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

Live demo pieces (the proxy also serves a presentation page at `http://127.0.0.1:8787/demo?token=<GUARD_PROXY_TOKEN>`:
type any prompt, it goes through the real guard and Crusoe, and the page shows what would have left, what left, and
what came back; the numbers below it are evidence, the live request is the point):

```bash
export GUARD_PROXY_TOKEN="$(openssl rand -hex 16)"
piiguard serve --host 0.0.0.0 --port 8787 --llm   # the guard proxy (holds the Crusoe + You.com keys)
python scripts/demo_leak.py --live           # same request direct vs guarded
bash nemoclaw/onboard.sh                     # NemoClaw sandbox whose only egress is the guard
```

## Routing: pay for a model only when the text earns it

With the classifier on, every request would cost a model call. Instead `piiguard/pii/router.py` scores what is
left after the regex rules ran (digit runs, base64-looking tokens, hex, spelled-out numbers, fullwidth digits,
percent-encoding, odd separators, id-shaped strings, name-shaped pairs, PII keywords) and picks a route:
**skip** (nothing suspicious remains and the text is short, no call), **small** (Nemotron 3.5 Lightning), or **large**
(Nemotron 3 Super, for broad or long inputs). Skip is deliberately narrow: longer zero-signal prose still gets the
small model, because semantic PII can have no shape at all. That is the fail-closed default; it is a one-line knob. The demo page shows the route and the milliseconds for every request. The policy is one
pure function behind the classifier interface; NVIDIA NeMo Switchyard (`pip install nemo-switchyard`, 0.3.0) ships a
`stage_router` for exactly this kind of signal-driven escalation and is the production home for that verdict.

## Using it on your own agent

The guard is a drop-in replacement for the model URL. The agent does not change.

1. On the machine that holds the keys, fill `.env` and start the proxy:
   ```bash
   export GUARD_PROXY_TOKEN="$(openssl rand -hex 16)"
   piiguard serve --host 0.0.0.0 --port 8787 --llm
   ```
2. Point the agent at it: base URL `http://<host>:8787/v1`, API key = the proxy token. Any OpenAI-compatible client
   works. For a NemoClaw sandbox, run `nemoclaw/onboard.sh` (custom provider pointing at the proxy) and apply
   `nemoclaw/piiguard-egress.yaml` so the sandbox can reach nothing else. Web search goes through `/you/search`.
3. Let it harden on your traffic and keep the result under review:
   ```bash
   piiguard gen-attacks --n 150 && piiguard improve --generations 6 && piiguard prune --gen 7 && piiguard bench --llm
   ```
   The product of the loop is `guard/rules.yaml` + `guard/prompt.md` in git: a security reviewer reads a diff, not a model.

Known limits: single host and token auth (a team deployment needs a real identity layer); streaming replies are
converted, not passed through; names are caught only with the classifier on; the loop has seen a synthetic red
team, not production traffic.

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
- The proxy inspects every string in the request (tool-call arguments, tool results, all content parts),
  uses one token namespace per request, binds to loopback by default, and refuses a non-loopback bind
  without an explicit token. Tokens are compared in constant time.
- All seed PII is synthetic: never-issued 9xx SSNs, 555-01xx phones, public card test numbers, example.com emails.
