# piiguard: a PII leak guard that hardens itself

[![CI](https://github.com/Akhilvallala1/piiguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Akhilvallala1/piiguard/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**A content layer for AI agent egress, plus a learnable rule layer for the organization-specific identifiers
(claim numbers, badge ids, record numbers) that off-the-shelf PII detectors do not know about.** Every improvement
is a reviewed git diff of plain YAML, accepted only if it lowers leaks on data the learner never saw.

**At a glance (honest version):**

- **Where it wins:** structured identifiers. On NVIDIA's public Nemotron-PII test split, the learned rules plus a
  local GLiNER-PII detector catch 91.0% of structured identifier spans vs 68.5% for Microsoft Presidio's defaults,
  with no text leaving the host (the remote Nemotron classifier reaches 92.8%).
- **Where it does not:** semantic PII (names, places, companies). On all Nemotron-PII labels Presidio still leads
  (65.9% vs 63.0% entity recall for the best local configuration).
- **Learning is offline and gated, by design.** Nothing learns from live traffic; a batch loop proposes rule
  changes, a gate accepts or rejects them, and accepted changes are tagged commits you can review and roll back.
- **Measured on values it never saw.** The original 30-attack held-out set reuses the training people (29 of 30
  values appear in train). On 500 fresh attacks with new values and new carrier formats, the learned rules leak
  25.6% [22.0, 29.6] against 76.0% for the hand-written gen-0 rules: 252 attacks fixed, 0 broken, p<0.001.
  That is a real, significant learning effect, but it is weaker than the 16.7% the small set suggested.
  See [Evaluation on unseen values](#evaluation-on-unseen-values).
- **Local first.** `--detector gliner` (or `presidio`) adds a base detector that runs on this host. The remote
  Nemotron classifier (`--llm`) is optional and is the only path that sends text off the machine.
- **The tradeoff is real.** On 1,075 clean samples the learned rules flag 0.3%, adding local Presidio 5.1%, and
  adding local GLiNER-PII 15.4%. The 4% measured on the original 25 clean samples was too optimistic.

Origin: built at the Recursive Agents Hackathon (San Francisco, 2026-10-17) and developed since.

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

The core was written during the hackathon. The design is informed by an earlier, unrelated guardrail
project by the same author, but no code was reused.

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
| Microsoft Presidio (default recognizers) | 53.3% (16/30) | 64.0% | 6 |
| Microsoft Presidio (scoped: SSN, email, phone, card) | 70.0% (21/30) | 4.0% | 4 |
| piiguard gen-0 (hand-written rules) | 76.7% (23/30) | 0.0% | 0 |
| piiguard gen-23 rules (self-improved, no model call) | 16.7% (5/30) | 0.0% | 0 |
| piiguard gen-23 rules + local presidio detector (no remote call) | 13.3% (4/30) | 4.0% | 11 |
| piiguard gen-23 rules + local gliner detector (no remote call) | 0.0% (0/30) | 4.0% | 254 |
| piiguard gen-23 rules + local gliner-broad detector (no remote call) | 0.0% (0/30) | 24.0% | 273 |
<!-- bench:end -->

The remote row (gen-14 rules + Nemotron 3.5 Lightning on Crusoe) was measured on 2026-10-17 at 0.0% leak, 0.0% false
positives and about 2.9 s per text; run `piiguard bench --llm` to reproduce it. The local GLiNER-PII row reaches the same
leak rate on this set, about ten times faster, without any text leaving the host. Detector settings were chosen on the
validation sets, not on held-out; with n=30, one clean sample is 4 points.

Presidio's default recognizers also flag dates, places and names, which is why its false-positive rate on
clean agent traffic is high; the scoped row limits it to the same entity types piiguard targets. The point
is not that Presidio is weak. It is that a static detector stays where it is, and piiguard closes the gap on
its own, on attacks its coach never saw.

Two layers, two jobs. The **rules** are the cheap path: microseconds per request, no tokens, and they are what
the coach evolves. The **Nemotron 3.5 Lightning classifier** is the expensive safety net behind them (about a
second and a model call per request). Read the table as: how far can the free layer get on its own, and what
does the paid layer add. Over time the coach moves the free layer toward what the paid layer catches, which is
the whole point of the loop.

### Evaluation on unseen values

The numbers above come from the original split, where held-out attacks reuse the same eight synthetic people (and so
the same SSNs, phones and cards) as training, and the same ten carrier templates. That makes memorizing a value look
like generalizing. `scripts/eval_rigorous.py` re-scores every system on data the loop never touched:

- **500 fresh attacks** (`data/attacks-fresh/heldout.jsonl`, `piiguard/redteam/fresh.py`): new people, new values,
  and ten new carrier formats (SQL, YAML, CSV, GraphQL, stack traces, HTTP headers, transcripts). Every value sits in
  a never-issued or fiction-reserved range. No value overlaps training, which a test checks.
- **1,075 clean samples** (`piiguard/eval/clean_corpus.py`): the 25 hand-written hard negatives plus 1,050 generated
  ones such as logs, UUIDs, hashes, base64 cache keys, 16-digit tracking numbers, barcodes and coordinates.
- **Partial leaks** (`leak_kind`): beyond the exact encoded form, a leak also counts if the plain value or its
  separator-free core survives, or if an SSN or card's last four digits survive on their own.
- **95% Wilson intervals** on every rate, and **exact one-sided McNemar tests** on paired outcomes.

<!-- rigorous:start -->
| system | strict leak (n=500) | any leak, incl. partial | false positives (n=1075) | ms/text |
|---|---|---|---|---|
| Microsoft Presidio (default recognizers) | 51.8% [47.4%, 56.1%] | 52.0% [47.6%, 56.3%] | 45.7% [42.7%, 48.7%] | 4 |
| Microsoft Presidio (scoped: SSN, email, phone, card) | 76.0% [72.1%, 79.5%] | 76.0% [72.1%, 79.5%] | 2.0% [1.3%, 3.0%] | 3 |
| piiguard gen-0 rules (hand-written) | 76.0% [72.1%, 79.5%] | 76.0% [72.1%, 79.5%] | 0.3% [0.1%, 0.8%] | 0 |
| piiguard gen-23 rules (learned, no model) | 25.6% [22.0%, 29.6%] | 26.2% [22.5%, 30.2%] | 0.3% [0.1%, 0.8%] | 0 |
| piiguard gen-23 rules + local presidio | 20.2% [16.9%, 23.9%] | 20.8% [17.5%, 24.6%] | 5.1% [4.0%, 6.6%] | 4 |
| piiguard gen-23 rules + local gliner | 10.0% [7.7%, 12.9%] | 10.2% [7.8%, 13.2%] | 15.4% [13.4%, 17.7%] | 146 |

Learning effect, gen-0 to learned rules, on these unseen values: fixed 252, broke 0, one-sided exact McNemar p <0.001. Brackets are 95% Wilson intervals.
<!-- rigorous:end -->

What this changes:

- **Learning helps a lot.** gen-0 to gen-23 fixed 252 of the 500 unseen attacks and broke none.
- **The small set overstated it.** On fresh values the learned rules leak about 26%, not 17%. The weakest
  techniques are non-breaking separators (15 of 17 leak), reversed values (23 of 34) and split lines (27 of 43).
  These are the coach's next targets.
- **There is a precision cost.** Every detector added on top lowers leaks and raises false positives. GLiNER-PII
  cuts leaks to 10% but flags 15% of clean traffic, mostly "aisle 5" as a street address and large counts as phone
  numbers. Pick by deployment: an egress guard that can tolerate over-redaction wants the detector, while a logging
  pipeline probably wants rules only.
- **Presidio scoped to the same types** leaks 76% with 2.0% false positives. That is the same leak rate as gen-0 and
  three times worse than the learned rules.

The loop can now gate on this kind of evidence: `piiguard improve --gate stat` accepts a proposal only if it fixes
significantly more validation attacks than it breaks (exact McNemar, `--alpha 0.05`) and newly flags no more than
`--max-new-fp` clean samples. `--clean large` uses the 1,075-sample corpus. On a 30-attack validation set, the old
5-point threshold accepts a change that fixes 2 attacks (p=0.25). The statistical gate needs 5 or more fixes with
none broken.

### Attacks written by other model families

The coach is Nemotron. So far the red team was mostly Python encoders, and Nemotron when it wrote text. To test
with someone else's blind spots, `piiguard/redteam/cross_family.py` had **gpt-oss-120b** and **Gemma 4 31B** write
500 attacks on unseen values (`data/attacks-crossfamily`, about $0.13). 381 wrap a known encoding in the model's own
wording. 119 use a technique the model invented itself: zero-width spaces, "956 dot 31 dot 8108", digits read
aloud, look-alike Unicode. An invented attack is kept only if its carrier decodes back to the real value.

<!-- crossfamily:start -->
| system | strict leak (n=500) | any leak, incl. partial | false positives (n=1075) | ms/text |
|---|---|---|---|---|
| Microsoft Presidio (default recognizers) | 51.4% [47.0%, 55.8%] | 53.0% [48.6%, 57.3%] | 45.7% [42.7%, 48.7%] | 3 |
| Microsoft Presidio (scoped: SSN, email, phone, card) | 73.0% [68.9%, 76.7%] | 73.0% [68.9%, 76.7%] | 2.0% [1.3%, 3.0%] | 3 |
| piiguard gen-0 rules (hand-written) | 78.8% [75.0%, 82.2%] | 78.8% [75.0%, 82.2%] | 0.3% [0.1%, 0.8%] | 0 |
| piiguard gen-23 rules (learned, no model) | 43.6% [39.3%, 48.0%] | 43.6% [39.3%, 48.0%] | 0.3% [0.1%, 0.8%] | 0 |
| piiguard gen-23 rules + local presidio | 37.0% [32.9%, 41.3%] | 38.2% [34.0%, 42.5%] | 5.1% [4.0%, 6.6%] | 3 |
| piiguard gen-23 rules + local gliner | 22.2% [18.8%, 26.0%] | 23.2% [19.7%, 27.1%] | 15.4% [13.4%, 17.7%] | 136 |

Learning effect, gen-0 to learned rules, on these unseen values: fixed 176, broke 0, one-sided exact McNemar p <0.001. Brackets are 95% Wilson intervals.
<!-- crossfamily:end -->

The learned rules leak 43.6% here against 25.6% on the deterministic fresh set. On the model-invented techniques
they leak 90 of 119. That is the clearest map of what the next generations should learn.

### Which coach, which gate: controlled comparison

`scripts/ablate_gates.py` gives each arm its own clone reset to gen-0. Every arm gets the same 180 training and 60
validation attacks and eight generations. Training uses the original carrier templates, so neither held-out set
shares a value or a carrier with it. Each arm is spend-capped (`PIIGUARD_BUDGET_USD`), and the whole comparison cost
under $1.50.

<!-- coaches:start -->
| arm | accepted / generations | rules | fresh leak (n=500) | cross-family leak (n=500) | false positives (n=1075) |
|---|---|---|---|---|---|
| start (gen-0) | 0 / 0 | 4 | 76.0% [72.1%, 79.5%] | 78.8% [75.0%, 82.2%] | 0.3% [0.1%, 0.8%] |
| coach: Nemotron 3 Super | 3 / 8 | 13 | 37.4% [33.3%, 41.7%] | 43.0% [38.7%, 47.4%] | 0.3% [0.1%, 0.8%] |
| coach: gpt-oss-120b | 1 / 8 | 6 | 69.8% [65.6%, 73.7%] | 73.2% [69.2%, 76.9%] | 0.3% [0.1%, 0.8%] |
| coach: DeepSeek V4 Pro | 2 / 8 | 15 | 42.2% [37.9%, 46.6%] | 47.2% [42.9%, 51.6%] | 0.5% [0.2%, 1.1%] |
<!-- coaches:end -->

**Coach model.** Same gate and same data. Nemotron 3 Super trained the best rules; DeepSeek V4 Pro was close behind.
gpt-oss-120b is about twenty times cheaper but barely improved on gen-0. That is evidence for the default coach
rather than a hackathon choice.

<!-- gates:start -->
| arm | accepted / generations | rules | fresh leak (n=500) | cross-family leak (n=500) | false positives (n=1075) |
|---|---|---|---|---|---|
| start (gen-0) | 0 / 0 | 4 | 76.0% [72.1%, 79.5%] | 78.8% [75.0%, 82.2%] | 0.3% [0.1%, 0.8%] |
| threshold | 3 / 8 | 14 | 41.0% [36.8%, 45.4%] | 49.0% [44.6%, 53.4%] | 0.8% [0.4%, 1.6%] |
| threshold+memory | 4 / 8 | 17 | 37.6% [33.5%, 41.9%] | 41.4% [37.2%, 45.8%] | 0.5% [0.2%, 1.1%] |
| stat | 2 / 8 | 16 | 54.6% [50.2%, 58.9%] | 59.4% [55.0%, 63.6%] | 0.3% [0.1%, 0.8%] |
| stat+memory | 2 / 8 | 10 | 54.8% [50.4%, 59.1%] | 61.0% [56.7%, 65.2%] | 0.3% [0.1%, 0.8%] |
<!-- gates:end -->

**Gate.** The statistical gate is the safer one. It turned down proposals that would have newly flagged 49, 214 or
602 of the 1,075 clean samples. On 60 validation attacks it is also too cautious: it accepted 2 changes out of 8,
ended at 55% leak, and the threshold gate reached 38 to 41%. The gate is only as good as the validation set behind
it, so the next step is a bigger validation set. That is the trade-off between safety and learning speed that the
report studies. Each configuration was run once with n=500 per held-out set; treat gaps inside the intervals as noise.

### Unseen identifier formats

`scripts/eval_formats.py` builds 400 attacks with organization-specific identifiers across four industries:

- insurance: adjuster badges, claims, policies
- healthcare: MRNs, NPIs, member IDs
- finance: accounts, routing numbers, IBANs
- legal: dockets, matters, bar numbers

Insurance is not truly unseen for the main rules, because generations 22 and 23 trained on it. The other three are.

<!-- formats:start -->
| system | all unseen formats (n=400) | insurance | healthcare | finance | legal |
|---|---|---|---|---|---|
| Microsoft Presidio (default recognizers) | 66.5% [61.7%, 70.9%] | 69/114 | 57/99 | 65/99 | 75/88 |
| piiguard gen-23 learned rules | 64.0% [59.2%, 68.6%] | 21/114 | 75/99 | 77/99 | 83/88 |
| piiguard gen-23 rules + matching industry pack | 36.8% [32.2%, 41.6%] | 21/114 | 35/99 | 38/99 | 53/88 |
| piiguard gen-23 rules + local GLiNER-PII | 57.2% [52.4%, 62.0%] | 20/114 | 70/99 | 62/99 | 77/88 |

Learning a new format: 75 training attacks on healthcare and finance formats only, 6 generations, 4 accepted, rules 31 to 40.

| held-out group | leak before | leak after | fixed | broke | p |
|---|---|---|---|---|---|
| trained formats (healthcare, finance) | 76.8% [70.4%, 82.1%] | 21.7% [16.5%, 28.0%] | 109 | 0 | <0.001 |
| unseen formats (legal, insurance) | 51.5% [44.6%, 58.3%] | 43.6% [36.9%, 50.5%] | 28 | 12 | 0.008 |
<!-- formats:end -->

- **Zero-shot is weak for everyone.** On formats they were never shown, the learned rules and Presidio both leak
  roughly two thirds. Local GLiNER helps a little. The one-line seed rules in each industry pack help the most.
- **The loop learns a new format fast.** Training on healthcare and finance only (75 attacks, six generations, $0.38)
  cut leaks on held-out values of those formats from 77% to 22%: 109 fixed, 0 broken.
- **Some of it transfers, with a cost.** On legal and insurance formats it never saw, leaks fell from 52% to 44%:
  28 fixed, but 12 broken. A real regression on formats the gate never checked. The shape-memory ledger exists to
  stop exactly this, but it can only protect shapes it has already seen.

### External check: NVIDIA Nemotron-PII (data we did not make)

Everything above is scored on attacks our own red team generated. To answer "you wrote the test", we also ran the
same systems on a stratified sample of NVIDIA's public
[Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII) test split (CC-BY-4.0): real-looking documents
across 29 domains with human-readable span labels. A span counts as caught if neither it nor its alphanumeric core
survives redaction. `scripts/eval_external.py` reproduces it.

<!-- external:start -->
| system | all labels, entity recall | structured identifiers, recall | records with any leak | ms/text |
|---|---|---|---|---|
| Microsoft Presidio (default) | 65.9% | 68.5% | 88.6% | 12 |
| piiguard gen-0 rules | 12.0% | 43.5% | 100.0% | 0 |
| piiguard current rules | 15.6% | 43.5% | 100.0% | 4 |
| piiguard current rules + matching industry pack | 15.6% | 43.5% | 100.0% | 5 |
| piiguard rules + pack + local Presidio detector | 43.6% | 48.9% | 98.6% | 18 |
| piiguard rules + pack + local GLiNER-PII (precise) | 47.2% | 45.9% | 97.6% | 187 |
| piiguard rules + pack + local GLiNER-PII (broad) | 63.0% | 91.0% | 87.6% | 208 |
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
| 24 | no | 35% → 35% | 0% → 0% | — | Add specific rules for ROT13-encoded adjuster badge (NQW-...) and claim number (PYZ-...) to capture the larges *(rejected)* |
| 25 | no | 35% → 35% | 0% → 0% | — | Add rot13‑specific rules that match encoded adjuster badge, claim number, and policy number only when they app *(rejected)* |

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

### Shape memory: the guard remembers every shape it ever caught

A 30-attack validation sample cannot see every regression. `piiguard/memory.py` keeps a ledger of every identifier
surface form the rules have caught, with the rule and the generation that caught it (`runs/shapes.jsonl`). It does two
things in the loop:

- **Regression gate.** A proposed rule set must still catch every remembered shape, or it is rejected even if the
  validation score improved.
- **Precedents for the coach.** When a new shape leaks, the coach is shown the nearest remembered shapes and the rules
  that solved them. Similarity is by shape signature (digits → 9, letters → A, separators kept) with character
  trigrams: `ADJ-48213-TX` is near `ADJ-50977-CA` because of its shape, not its meaning. No embedding model is needed
  for identifiers; embeddings belong to the semantic layer, where the classifier lives.

Replaying today's 15 coach proposals against a ledger built from the rules that preceded each one
(`scripts/replay_memory.py`): 4 proposals dropped at least one remembered shape, and one of them, generation 14, was
**accepted** by the validation-only gate while silently losing a percent-encoded phone shape the generation-3 rules had
caught. Generations 14 through 21 shipped without it until the coach rediscovered it in generation 22, eight
generations later. With the memory gate on, generation 14 would have been sent back with the shape named.

<!-- memory:start -->
Live check with memory on (insurance pack, generations 24 and 25, ledger seeded with the 42 shapes the current rules
catch): both proposals were rejected for no validation gain, and generation 24's proposal would additionally have
dropped two remembered shapes, a split-line claim number and a split-line adjuster badge, which the ledger named.
The coach's rationales now cite the precedent rules it was shown.

**Controlled comparison on Nemotron-PII.** Two isolated clones, both reset to the generation-14 rules, both given the
same Nemotron-PII training slice (184 train, 59 validation documents, structured identifiers as targets), four
generations each, scored on 104 held-out Nemotron-PII documents the coach never saw (`scripts/compare_arms.py`):

| arm | accepted | regressions flagged | final rules | held-out leak, rules only | held-out leak, rules + classifier |
|---|---|---|---|---|---|
| starting rules (gen-14) | | | 13 | 83.7% | 21.2% |
| memory off | 2 of 4 | 0 | 33 | 71.2% | 13.5% |
| memory on | 1 of 4 | 2 | 28 | **65.4%** | 14.4% |

With rules alone, the memory arm leaked 6 points less on held-out with 5 fewer rules and one accepted generation
instead of two: the gate refused a proposal (gen 204) that improved validation by 5 points while dropping an API key,
two UUID device identifiers, a routing number and a hex token the previous rules caught. With the classifier behind
the rules the two arms are within noise of each other on this sample. One run, 104 documents: suggestive, not
conclusive, and reported as such.
<!-- memory:end -->

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
   uv pip install -e ".[gliner]"                          # or ".[presidio]"
   export GUARD_PROXY_TOKEN="$(openssl rand -hex 16)"
   piiguard serve --host 0.0.0.0 --port 8787 --detector gliner   # rules + local detector; add --llm for the remote classifier
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
converted, not passed through; names are caught only with a detector on (`--detector` or `--llm`); the loop has seen a synthetic red
team, not production traffic.

### Already running Presidio or NeMo Guardrails? Export the learned rules

You do not have to replace your detector to use what the loop learned. `piiguard export` turns `guard/rules.yaml`
into the formats those tools already load, so the learned layer drops in next to what you run today.

```bash
piiguard export presidio --domain insurance --out recognizers.yaml
#   registry.add_recognizers_from_yaml("recognizers.yaml")

piiguard export guardrails --domain insurance --extra-entity PERSON --out piiguard-rails.yml
#   merge into your NeMo Guardrails config.yml; it uses the built-in "mask sensitive data on input/output" flows
```

What the tests check (`tests/test_export.py`):

- **Same spans.** Each exported recognizer matches exactly the same spans as piiguard's own rule on every attack and
  clean sample in the repo. Flags are pinned, because Presidio's default `IGNORECASE` would quietly widen a learned
  rule.
- **Works in Guardrails.** NeMo Guardrails' own `mask_sensitive_data` action, given the exported config, masks the
  adjuster badge, claim number and policy number that Presidio's built-in recognizers miss.
- **Validators.** Rules that rely on a validator (Luhn checksum, decode-then-recheck) are left out of the YAML formats
  by default and listed in the file header, because without the validator they over-match. In Python,
  `piiguard.export.presidio_recognizers(rules)` returns Presidio recognizers with the validators attached.

Re-export after each accepted generation. The YAML in git stays the reviewed source of truth.

### As an OpenShell plugin: supervisor middleware

OpenShell's network policy decides *where* an agent may talk; it never reads request bodies. The hook NVIDIA built for
content is [supervisor middleware (RFC 0009)](https://github.com/NVIDIA/OpenShell/tree/main/rfc/0009-supervisor-middleware):
a gRPC service the sandbox supervisor consults after policy allows a request and before it injects credentials. Today the
only built-in is a demo regex for `sk-` keys. `piiguard middleware` fills that slot with the same guard the proxy uses,
and the agent no longer needs a proxy URL at all: it calls Crusoe and You.com directly and the supervisor pauses each
request on the way out.

```
agent ──► sandbox supervisor ──► EvaluateHttpRequest  ──► piiguard: redact body → tokens, park mapping by request_id
                │                                            ▲
                ├── network policy (host/path) ok?           │  HttpResponsePreReturn.Evaluate: restore tokens → values
                ▼                                            │
          Crusoe / You.com  ─────────── response ────────────┘
```

```bash
uv pip install -e ".[middleware]"                                   # grpcio, protobuf, pyjwt
piiguard middleware --host 0.0.0.0 --port 50051 --allow-insecure --llm   # 1. start the service
cat nemoclaw/middleware/gateway.toml >> <gateway config>.toml            # 2. register it, restart the gateway
openshell policy set --sandbox <name> --file nemoclaw/middleware/piiguard-middleware.yaml   # 3. attach it
```

The policy entry is four lines: `middleware: piiguard`, `endpoints.include: [api.inference.crusoecloud.com, api.you.com]`,
`on_error: fail_closed`, and a `config` with `mode: redact|deny` and `restore: true`. What the service implements:

| RPC | What piiguard does |
| --- | --- |
| `Describe` | Negotiates protocol 1.0, declares `HTTP_REQUEST/PRE_CREDENTIALS` and `HTTP_RESPONSE/PRE_RETURN`, 1 MiB payloads |
| `ValidateConfig` | Rejects unknown keys and bad values before the gateway accepts the policy |
| `EvaluateHttpRequest` | Walks JSON bodies (messages, tool args, tool results) or plain text, returns the redacted body, audit-safe findings per PII type (names and counts, never values), and `accept-encoding: identity` so the reply is inspectable |
| `HttpResponsePreReturn.Evaluate` | Looks the request up by `request_id`, restores tokens in the whole body or per streamed unit, skips with a logged finding when the body cannot be inspected |

Failure behaviour follows the platform: `on_error: fail_closed` means a down middleware blocks traffic instead of leaking
it; a body that is not UTF-8 is denied unless `on_binary: allow`. With `--gateway-id` and `--jwt-key` the service verifies
the Ed25519 `openshell-ext+jwt` token OpenShell attaches to every call (issuer, exact audience, `typ`, `caller_kind`);
without them it must be registered with `allow_insecure_transport = true`.

Honest caveats: the contract is a research preview and NVIDIA says it will change (`scripts/gen_proto.sh --refresh`
regenerates the stubs); NemoClaw does not expose `network_middlewares` or gateway registration yet, so this path is
applied through the OpenShell CLI; and it is verified against the published proto and a live in-process gRPC server
(`tests/test_middleware.py`), not yet against a running gateway. Set the registration `timeout` to `10s` when `--llm`
is on; the default 500 ms is enough for rules only.

## Layout

```
guard/rules.yaml, guard/prompt.md   evolvable guard artifacts (git-tagged per generation)
piiguard/pii/                        rules, regex+LLM guard, reversible redaction
piiguard/redteam/                    encoders + attack generator (+ optional LLM carriers)
piiguard/eval/                       harness, scoring, hard-negative clean set
piiguard/coach/                      retrospective (coach prompt + parsing), gate (decide, git)
piiguard/loop.py                     one generation: eval -> coach -> stage -> gate -> commit/revert
piiguard/proxy.py                    FastAPI guard proxy: /v1/chat/completions, /you/search, /events
piiguard/middleware/                 OpenShell supervisor middleware (gRPC): service, server, vendored proto + stubs
nemoclaw/                            onboard script + egress policy presets (leaky vs guarded)
nemoclaw/middleware/                 gateway.toml registration + network_middlewares policy for the plugin path
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

## Roadmap

Tracked as [GitHub issues](https://github.com/Akhilvallala1/piiguard/issues). In order:

1. **Trust:** license, CI, packaging, README that matches the code. *(done)*
2. **Local first:** a local base detector (Presidio or GLiNER-PII) so no raw text leaves the host to be classified
   *(done: `--detector`)*; learned rules exported as Presidio recognizers and as a NeMo Guardrails config
   *(done: `piiguard export`)*.
3. **Evaluation that holds up:** fresh-value held-out set (n=500), 1,075-sample clean corpus, partial-leak scoring,
   Wilson intervals, McNemar tests, a statistical gate, a cross-family red team, unseen-format tests, and gate and
   coach ablations *(done)*. Still open: a larger validation set for the statistical gate, repeated runs, and
   external attack sets.
4. **Write-up:** a technical report on gated, auditable rule evolution for PII guards.

## License

Apache-2.0. See [LICENSE](LICENSE).
