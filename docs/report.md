# Gated, auditable rule evolution for PII guards

**Akhil Vallala**. Technical report, October 2026. Code, data and every number below:
<https://github.com/Akhilvallala1/piiguard>. Every number is taken from a JSON file under `runs/`, which the scripts
listed in Reproducing regenerate.

## Abstract

AI agents send text to model APIs, search engines and tools. A sandbox such as NVIDIA OpenShell decides *where* that
text may go, but not *what* is in it. So an allowed request can still carry a customer's SSN.

We study a content guard that improves itself under supervision. A language-model coach proposes changes to a set
of regex rules. A gate accepts a change only if it lowers leaks on validation data without adding false positives.
Every accepted change becomes a tagged git commit that a person can read and roll back.

We evaluate on data the loop never touched:

- 500 attacks with fresh values
- 500 attacks written by other model families
- 400 organization-specific identifier formats
- 1,075 clean samples

Results:

- **Learning is real.** On unseen values, the learned rules fix 252 attacks that the hand-written baseline leaked
  and break none (exact McNemar p < 0.001). Leak falls from 76.0% to 25.6%.
- **Coach choice matters.** With the same data and gate, Nemotron 3 Super trains better rules than DeepSeek V4 Pro,
  and both beat gpt-oss-120b by a wide margin.
- **A statistical gate is safer but slower.** It blocks proposals that would newly flag up to 602 clean samples, but
  with 60 validation attacks it accepts too little to learn quickly.
- **The loop does not invent defenses.** It learns the obfuscation techniques it is shown. Holding a technique out of
  training removes most of the gain on that technique. The exception is a technique whose decoder the coach already
  has in its toolbox.
- **New formats are learned quickly.** The loop learns a new identifier format from 75 examples for $0.38. It also
  partly transfers to formats it never saw, but breaks 12 attacks there.

We report these limits alongside the gains. The total model spend for all experiments was under $5, estimated from
token counts. The first gate run did not log its spend.

## 1. Problem

An agent inside a sandbox has an egress policy, for example "Crusoe for inference, You.com for search". Policies
match host, port, path and binary, not the request body. The agent can therefore paste a customer record into a
search query, and the policy allows it.

A content guard closes this gap. It replaces PII in outbound payloads with reversible tokens (`[PII_SSN_1]`),
forwards the request, and restores the values in the response. The agent finishes its task, and the third party
never sees the value.

Two things make a static guard insufficient:

1. **Organization-specific identifiers.** An insurer's adjuster badge (`ADJ-48213-TX`) is PII to the insurer. No
   off-the-shelf recognizer knows it.
2. **Obfuscation.** Agents and attackers move values through base64, hex, spelled-out digits, reversed strings,
   look-alike Unicode, zero-width spaces and line breaks.

The guard has to grow. The question this report studies is how to let it grow without letting it grow wrong.

## 2. Method

### 2.1 Guard

The guard runs these steps on every outbound string:

1. **Regex rules.** Each rule may carry a *validator*: a Luhn checksum, or a decode-then-recheck that decodes the
   match as base64, hex, percent-encoding or reversed text and fires only if the plain rules match the result.
   This lets a broad pattern ("any 12+ hex characters") stay precise.
2. **Optional local detector.** Presidio or GLiNER-PII runs on the host, so no text leaves the machine to be
   classified.
3. **Optional remote classifier.** An LLM, routed by a cheap complexity score.
4. **Merge and redact.** Overlapping findings are merged into one span, so no fragment survives, and replaced with
   tokens.

If any rule takes longer than its time budget on a string, the whole string is withheld (fail closed).

### 2.2 The loop

One generation:

1. **Evaluate** the current rules on the training attacks and collect the misses.
2. **Coach.** An LLM reads the misses, the current `rules.yaml`, the validator list and its own past rationales,
   then proposes a new rule set. Proposed regexes are checked before use: length cap, no nested quantifiers, and a
   timing probe against adversarial input.
3. **Gate.** Validation leak and clean false positives are measured before and after the proposed change.
4. **Commit or revert.** An accepted proposal becomes a git commit tagged `gen-N`. A rejected one is reverted and
   logged with the reason.

Two gates are compared:

- **Threshold gate.** Accept if validation leak drops by at least 5 points and the clean false-positive rate rises by
  at most 5 points.
- **Statistical gate.** Accept if the candidate fixes significantly more validation attacks than it breaks, by a
  one-sided exact McNemar test on paired outcomes (p < α), *and* newly flags at most k clean samples. The clean set
  for this gate is the 1,075-sample corpus.

**Shape memory** is an optional third check. A ledger records the surface shape of every identifier the rules have
caught (digits to 9, letters to A, separators kept). Any proposal that would stop catching a remembered shape is
rejected, even if validation improved.

### 2.3 Why gated and auditable

The product of the loop is a diff of plain YAML. A security reviewer reads two regex lines, not a model. Rolling
back is `git checkout gen-3 -- guard/`. Nothing learns from live traffic: the proxy runs a frozen rule set, and
learning is an offline batch job whose output is reviewed like any other change.

## 3. Evaluation design

The original 30-attack held-out split reused the training people: 29 of its 30 values appear in training. It also
used the same ten carrier templates as training. That rewards memorizing a value or a carrier and calls it
generalization. Every result below uses data built to avoid this.

| set | n | built from | overlaps training? |
|---|---|---|---|
| Fresh values | 500 | new synthetic people; 12 Python encoders; 10 new carriers (SQL, YAML, CSV, GraphQL, stack traces, HTTP headers, transcripts) | values: no (tested). Carriers: no. Techniques: **yes** |
| Cross-family | 500 | gpt-oss-120b and Gemma 4 31B. 381 wrap a known encoding in the model's own wording; 119 use a technique the model invented | values: no. Carriers: no. 119 techniques: new |
| Unseen formats | 400 | adjuster badges, claims, policies, MRNs, NPIs, member IDs, accounts, routing numbers, IBANs, dockets, matters, bar numbers | formats: unseen except insurance (see §4.5) |
| Clean corpus | 1,075 | 25 hand-written plus 1,050 generated hard negatives: logs, UUIDs, hashes, base64 cache keys, non-Luhn 16-digit tracking numbers, barcodes, coordinates | n/a |
| Nemotron-PII | 290 records, 2,630 spans | NVIDIA's public test split, written and labeled by others | none |

Every value is synthetic, and the sources are chosen so no real person is involved:

- SSN area 900 to 999 (never issued)
- phones in the 555-0100 to 0199 fiction block
- test card prefixes with valid Luhn digits
- RFC 2606 email domains

**Scoring.** A *strict* leak means the encoded surface form survives redaction. An *any* leak also counts when the
plain value survives, when its separator-free core survives, or when the last four digits of a value with 8 or more
digits survive on their own.

**Statistics.** Every rate carries a 95% Wilson interval. Every paired comparison uses an exact McNemar test.

**Controlled comparisons.** Each arm runs in its own git clone reset to gen-0. All arms get the same 180 training and
60 validation attacks (fresh values, original carriers) and the same number of generations. Each arm is
spend-capped by `PIIGUARD_BUDGET_USD`. The main repository's rules and tags are never touched.

## 4. Results

### 4.1 Does learning help on unseen values?

| system | strict leak, fresh (n=500) | strict leak, cross-family (n=500) | false positives (n=1,075) |
|---|---|---|---|
| Presidio, scoped to the same types | 76.0% [72.1, 79.5] | 73.0% [68.9, 76.7] | 2.0% [1.3, 3.0] |
| Presidio, default recognizers | 51.8% [47.4, 56.1] | 51.4% [47.0, 55.8] | 45.7% [42.7, 48.7] |
| piiguard gen-0 (hand-written) | 76.0% [72.1, 79.5] | 78.8% [75.0, 82.2] | 0.3% [0.1, 0.8] |
| piiguard gen-23 (learned) | **25.6% [22.0, 29.6]** | **43.6% [39.3, 48.0]** | **0.3% [0.1, 0.8]** |
| gen-23 + local Presidio | 20.2% [16.9, 23.9] | 37.0% [32.9, 41.3] | 5.1% [4.0, 6.6] |
| gen-23 + local GLiNER-PII | 10.0% [7.7, 12.9] | 22.2% [18.8, 26.0] | 15.4% [13.4, 17.7] |

From gen-0 to gen-23:

- **Fresh set:** 252 attacks fixed, 0 broken.
- **Cross-family set:** 176 fixed, 0 broken.

Both are p < 0.001. The learned rules add no false positives on the 1,075-sample corpus.

Two qualifications:

- **The original split overstated the effect.** On that small, overlapping split, gen-23 reported a 16.7% leak. On
  unseen values the figure is 25.6%.
- **Attacks from other model families are harder.** They leak 43.6% against 25.6%. On the 119 attacks where a model
  invented its own technique, 90 still leak, mostly zero-width spaces, words like "dot" between digit groups, and
  digits read aloud.

**Partial leaks are rare.** Counting value-in-another-shape and surviving last-four digits raises the learned rules'
leak rate by only about 1 point. Redaction almost always removes the whole value or none of it.

**Adding a local detector trades precision for recall.** GLiNER-PII cuts leaks to 10% but flags 15% of clean
traffic. Its false positives are mostly "aisle 5" read as a street address and large counts read as phone numbers.
The right choice depends on the deployment: an egress guard that tolerates over-redaction should use the detector,
and a logging pipeline probably should not.

### 4.2 Which coach?

Same statistical gate with memory, same data, eight generations, at most 5 new clean flags per change:

| coach | accepted | fresh leak | cross-family leak | false positives | estimated cost |
|---|---|---|---|---|---|
| Nemotron 3 Super 120B | 3 / 8 | **37.4% [33.3, 41.7]** | **43.0% [38.7, 47.4]** | 0.3% | $0.22 |
| DeepSeek V4 Pro | 2 / 8 | 42.2% [37.9, 46.6] | 47.2% [42.9, 51.6] | 0.5% | $0.15 |
| gpt-oss-120b | 1 / 8 | 69.8% [65.6, 73.7] | 73.2% [69.2, 76.9] | 0.3% | $0.01 |

Nemotron and DeepSeek overlap within their intervals. Both clearly beat gpt-oss, which is about twenty times cheaper
but barely improves on gen-0 (76.0%). One run per coach.

### 4.3 Which gate?

Same coach (Nemotron 3 Super), same data, eight generations:

| gate | accepted | rules | fresh leak | cross-family leak | false positives |
|---|---|---|---|---|---|
| threshold | 3 / 8 | 14 | 41.0% [36.8, 45.4] | 49.0% [44.6, 53.4] | 0.8% [0.4, 1.6] |
| threshold + memory | 4 / 8 | 17 | **37.6% [33.5, 41.9]** | **41.4% [37.2, 45.8]** | 0.5% [0.2, 1.1] |
| statistical | 2 / 8 | 16 | 54.6% [50.2, 58.9] | 59.4% [55.0, 63.6] | 0.3% [0.1, 0.8] |
| statistical + memory | 2 / 8 | 10 | 54.8% [50.4, 59.1] | 61.0% [56.7, 65.2] | 0.3% [0.1, 0.8] |

The statistical gate is the only configuration that adds **zero** false positives. In an earlier run with k = 0, it
rejected proposals that would have newly flagged 49, 214 and 602 of the 1,075 clean samples. The threshold gate,
measuring false positives on only 25 clean samples, cannot see failures of that kind.

The cost is learning speed. With 60 validation attacks, a real improvement of 3 or 4 fixed attacks does not reach
p < 0.05 (four fixed and none broken gives p = 0.0625). So the gate rejects changes that are probably good. The gate
can only be as good as the validation set it checks against.

Memory helped the threshold gate (37.6% vs 41.0% fresh, 41.4% vs 49.0% cross-family). It made no difference to the
statistical gate. Both effects are single runs and should be repeated.

One caveat on this table: the coach fell back to DeepSeek V4 Flash for one call in the statistical arm (3,898 input
tokens), after a Nemotron failure.

### 4.4 Does it generalize to techniques it never saw?

Training and the fresh set share all 12 encoders, so a good fresh score could mean the loop learned these 12 tricks
rather than learning to generalize. For six techniques, we trained from gen-0 with that technique removed from
training, then scored only that technique on unseen values:

| held out | leak, gen-0 | leak after training without it | fixed / broke | p |
|---|---|---|---|---|
| spelled-out digits | 100.0% | 100.0% | 0 / 0 | 1.000 |
| reversed | 67.6% | 67.6% | 0 / 0 | 1.000 |
| base64 | 100.0% | 89.4% | 5 / 0 | 0.031 |
| split across lines | 100.0% | 81.4% | 8 / 0 | 0.004 |
| non-breaking separators | 100.0% | 64.7% | 6 / 0 | 0.016 |
| hex | 100.0% | 21.3% | 37 / 0 | < 0.001 |

The same arms reduced leak on the techniques they *did* train on from about 75% to between 26% and 52%. So learning
happened, and it mostly did not transfer.

The hex result is not generalization. The coach's prompt lists piiguard's validators, including
`decodes_to_pii_hex`, so the coach can write a hex rule without ever seeing a hex attack. The small transfers to
split lines, separators and base64 come from broader digit and separator patterns.

**Conclusion.** The loop learns defenses for the obfuscations it is shown. It rarely invents one for an obfuscation
it is not shown, unless the decoding primitive is already in its toolbox. This is the central limitation of the
method, and it tells us where to invest: the red team's breadth matters more than the coach's cleverness.

### 4.5 Unseen identifier formats

**Zero-shot** (400 attacks):

| system | all | insurance | healthcare | finance | legal |
|---|---|---|---|---|---|
| Presidio | 66.5% | 69/114 | 57/99 | 65/99 | 75/88 |
| gen-23 learned rules | 64.0% | 21/114 | 75/99 | 77/99 | 83/88 |
| gen-23 + industry pack (seed rules) | 36.8% | 21/114 | 35/99 | 38/99 | 53/88 |
| gen-23 + local GLiNER-PII | 57.2% | 20/114 | 70/99 | 62/99 | 77/88 |

Insurance is not truly unseen for gen-23, because generations 22 and 23 trained on an insurance pack. On the three
truly unseen industries, every system leaks most attacks. The one-line seed rules in each industry pack help more
than any model.

**Learning a new format.** Starting from gen-23, an isolated clone trained on healthcare and finance formats only
(75 attacks, 6 generations, 4 accepted, $0.38):

| held-out group | leak before | leak after | fixed / broke | p |
|---|---|---|---|---|
| trained formats: healthcare, finance (n=198) | 76.8% | 21.7% | 109 / 0 | < 0.001 |
| unseen formats: legal, insurance (n=202) | 51.5% | 43.6% | 28 / 12 | 0.008 |

A new format is learned quickly and cheaply. Some of it transfers, but 12 attacks on unseen formats that used to be
caught now leak. This is a real regression on data the gate never saw. Shape memory exists to prevent exactly this,
but it can only protect shapes it has already seen.

### 4.6 External check: NVIDIA Nemotron-PII

On 290 records from NVIDIA's public test split:

| system | entity recall, all labels | recall, structured identifiers |
|---|---|---|
| Presidio (default) | **65.9%** | 68.5% |
| learned rules | 15.6% | 43.5% |
| rules + pack + local GLiNER-PII (broad) | 63.0% | 91.0% |
| rules + pack + remote Nemotron classifier | 58.3% | **92.8%** |

Presidio leads on all labels, because those include names, places and companies, which regex rules were never meant
to catch. On structured identifiers, the job a learnable rule layer is for, piiguard with a detector leads by more
than 20 points. The local detector gets within two points of the remote one without sending text off the host.

## 5. Threats to validity

| concern | status |
|---|---|
| Coach and attacker from the same family | Training and fresh attacks come from Python encoders, not a model. The cross-family set is written by gpt-oss-120b and Gemma 4. |
| Test values seen in training | Fixed. No value overlaps training, and a test checks this. |
| Test carriers seen in training | Fixed for all controlled comparisons. |
| Test techniques seen in training | Measured, not fixed (§4.4). Most techniques do not transfer. |
| Author wrote the scoring and the validity check | Open. Model-invented attacks are kept only if piiguard's decoder recovers the value. That favors tricks it can already decode, so the 90/119 leak rate on invented attacks is likely an *under*estimate. |
| No human-written attacks | Open. `data/attacks-human/` holds a contributor kit and `scripts/eval_human.py` scores it. |
| One run per configuration | Open. Differences inside the intervals should be read as noise. |
| Small validation sets in the gate | Open, and it directly limits the statistical gate (§4.3). |
| Cost estimates | Computed from token counts and public rates. Models without a public rate were charged at the highest listed rate. |

## 6. Related work and positioning

**Static detectors.** Presidio, GLiNER-PII and LLM classifiers decide what counts as PII from a fixed model or
recognizer set. piiguard does not replace them. It runs them as a base layer (`--detector`) and adds a learnable rule
layer on top. That layer exports to Presidio recognizers and NeMo Guardrails configs (`piiguard export`), so teams can
adopt it without changing tools.

**Self-improving systems.** Systems that let a model rewrite its own prompts or programs usually optimize a score
directly. The contribution here is the *gate*: proposals are untrusted, each change has to earn acceptance on paired
held-out evidence, and the product is a reviewable diff. The ablations show that this gate decides the outcome as
much as the coach does.

## 7. Conclusions and next steps

A coach plus a gate turns a small hand-written rule set into one that leaks a third as often on unseen values, with
no new false positives, for a few cents per generation. Every change is a diff a person can review and undo.

Three findings should shape what is built next:

1. **Breadth of the red team limits the guard more than the coach does.** The loop learns what it is shown and
   little else (§4.4). Invest in diverse, external attack sources: human-written attacks and other model families.
2. **A statistical gate needs data.** It prevents false-positive regressions that a small clean set cannot see. To
   learn at a useful speed it needs a validation set in the hundreds, not 60.
3. **Shape memory should cover formats, not only values.** The loop regressed on formats it never trained on (§4.5).

Planned follow-ups:

- human-written attack set
- repeated runs with seeds for every comparison
- validation sets of 300 or more for the statistical gate
- an LLM-checked validity filter for model-invented attacks, to replace piiguard's own decoder

## Reproducing

```bash
uv pip install -e ".[dev,presidio,gliner]"
python scripts/eval_rigorous.py                                   # §4.1, no API calls
RIGOR_SET=crossfamily python scripts/eval_rigorous.py             # §4.1 cross-family
PIIGUARD_BUDGET_USD=8 python scripts/ablate_gates.py --compare coaches --generations 8 --max-new-fp 5 --workdir ../ablation-coaches-v2
PIIGUARD_BUDGET_USD=8 python scripts/ablate_gates.py --compare gates   --generations 8 --max-new-fp 5 --workdir ../ablation-gates-v2
PIIGUARD_BUDGET_USD=2 python scripts/eval_holdout_technique.py --techniques reversed,spelled,hex,split_lines,unicode_separators,base64
PIIGUARD_BUDGET_USD=4 python scripts/eval_formats.py --learn
python scripts/eval_external.py                                   # §4.6, needs the Nemotron-PII parquet
```
