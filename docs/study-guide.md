# piiguard study guide

Read this end to end once, run the hands-on commands, then answer the self-test without looking. If you can do that,
you can explain piiguard to anyone, including an interviewer who pushes back.

---

## 1. The problem (one sentence you must own)

> A sandbox controls **where** an AI assistant's messages go. It never reads **what** is inside them.

NVIDIA's OpenShell or NemoClaw sandbox has a rule list like "allow the model provider, allow the search engine, deny
everything else". If the assistant puts a customer's SSN into a web search, the search engine is allowed, so the SSN
leaves. No rule was broken.

**Hands-on:** `python scripts/demo_leak.py` shows the same request sent directly and sent through the guard.

---

## 2. The filter (what runs on every message)

```
assistant writes:  "body shops near Maria Chen, SSN 912-34-5678"
what leaves:       "body shops near [PII_NAME_1], SSN [PII_SSN_1]"
reply comes back:  placeholders swapped back to the real values
```

| Piece | File | What to remember |
|---|---|---|
| Proxy | `piiguard/proxy.py` | Looks like an OpenAI endpoint. The assistant points at it instead of the real provider. It holds the API keys, so the sandbox never sees them. |
| Guard | `piiguard/pii/guard.py` | Scans, merges overlapping finds, swaps in placeholders, restores them in the reply. |
| Rules | `guard/rules.yaml` | Regex patterns. This is the file that learns. |
| Validators | `piiguard/pii/rules.py` | Extra checks on a match: the Luhn card checksum, or decode the text (base64, hex, URL encoding, reversed) and re-check it. |
| Local detector | `piiguard/pii/local.py` | GLiNER-PII or Presidio, on your machine. Catches names and places. |
| Remote classifier | `piiguard/pii/classifier.py`, `router.py` | Optional Nemotron call. A router decides whether it is needed. The only path that sends text out. |

**Key safety details** (interviewers love these):
- **Fail closed.** If a regex takes too long, the whole string is withheld, not sent unchecked.
- **Overlapping finds are merged**, so no fragment of a value survives. This is the same bug class as your Guardrails
  issue #2469.
- **New rules are vetted before use.** Rules written by the coach are checked for "catastrophic" regexes
  (length cap, no nested repeats, a timing probe) before they can run.

**Hands-on:**
```bash
python -m piiguard.cli redact -v "Maria Chen, SSN 912-34-5678, card 4111 1111 1111 1111"
python -m piiguard.cli redact --detector gliner -v "Maria Chen lives in Springfield"
```

---

## 3. The learning loop (what makes it different)

```
red team → test current rules → coach proposes new rules → GATE → keep (git tag gen-N) or revert
```

| Step | File | Plain words |
|---|---|---|
| Red team | `piiguard/redteam/encoders.py`, `generator.py` | 12 Python tricks: base64, hex, spaced digits, fullwidth digits, spelled out, split lines, URL encoding, ROT18, reversed, no separators, special separators, plain. |
| Coach | `piiguard/coach/retrospective.py` | Nemotron 3 Super reads the misses and writes new YAML. |
| Gate | `piiguard/coach/gate.py` | Accepts only proven improvements. |
| Memory | `piiguard/memory.py` | Remembers every ID shape ever caught; rejects changes that would forget one. |
| One generation | `piiguard/loop.py` | Glues the steps together. |

**The two gates:**
- **Threshold** (the original): leaks must drop 5 points and false positives must not rise more than 5 points.
  Simple, but on 30 test attacks, 5 points is 1.5 attacks. That is close to noise.
- **Statistical** (added in Phase 3): the change must fix *significantly* more attacks than it breaks (McNemar test),
  and must newly flag no more than k normal messages out of 1,075. Safer, but slower to learn.

**Why "auditable"?** Every accepted change is a git commit you can read. The command
`git diff gen-0 gen-23 -- guard/` shows everything the system ever learned, in plain YAML. Undo is one command.
Nothing learns from live traffic.

**Hands-on:**
```bash
git tag --list 'gen-*'
git diff gen-14 gen-22 -- guard/rules.yaml | head -40
python -m piiguard.cli report
```

---

## 4. The evidence (numbers to know by heart)

All from `docs/report.md`; every number traces to a file in `runs/`.

| Claim | Number |
|---|---|
| Leak on 500 brand-new values, hand-written rules → learned rules | **76% → 26%** |
| Attacks fixed / broken by learning | **252 / 0** |
| Normal text wrongly flagged (1,075 samples) | **0.3%** |
| Presidio limited to the same PII types, same 500 attacks | **76%** leak |
| Attacks written by gpt-oss and Gemma | **44%** leak |
| Structured IDs caught in NVIDIA's own Nemotron-PII data | **91–93%** vs Presidio **69%** |
| New company ID format learned from 75 examples | **77% → 22%** for **$0.38** |
| Best coach | Nemotron 3 Super, then DeepSeek V4 Pro; gpt-oss far behind |
| Total model spend for every experiment | **under $5** |

---

## 5. The limits (say these before anyone asks)

1. **It learns what it is shown.** Leave spelled-out digits out of training and it never learns them (0 fixed).
2. **Model-written attacks are harder:** 44% leak. When the model invents its own trick, 90 of 119 get through.
3. **Names and places:** Presidio is better (66% vs 63%).
4. **The statistical gate learns slowly** with 60 validation attacks.
5. **Learning new formats can break others:** 28 fixed but 12 broken on formats it never trained on.
6. **No human-written attacks yet.** The kit is in `data/attacks-human/`.
7. **One run per experiment,** so small differences are noise.

The original "76.7% → 16.7%" from the hackathon was too optimistic: 29 of 30 test values had appeared in training.
The honest number on new values is 26%. Saying this yourself builds trust.

---

## 6. Likely questions and short answers

**"Isn't an LLM writing regexes dangerous?"**
Its output is untrusted. Every regex is checked for slowness before use, every change must pass the gate, and a
person can read and revert every change.

**"Why not just use Presidio or an LLM?"**
Use them. piiguard runs them as a base layer and exports its learned rules *into* Presidio and NeMo Guardrails.
What they lack is a way to learn your company's own IDs safely.

**"Aren't you grading your own homework?"**
Partly, and the report says where:
- **Independent:** NVIDIA's dataset, plus attacks written by other model families.
- **Measured:** the hold-out test shows the honest limit.
- **Still open:** attacks written by people.

**"Does it learn online from real traffic?"**
No, on purpose. Learning is an offline batch job; the proxy runs frozen, reviewed rules.

**"What's actually new here?"**
Not the AI-writes-rules part. The gate is new: proposals are untrusted, must win on paired held-out evidence, and
ship as reviewable diffs. The experiments show the gate shapes results as much as the coach does.

**"What would you do next?"**
Human-written attacks; a larger validation set so the statistical gate can learn faster; shape memory for formats,
not just values.

---

## 7. Self-test (answer without looking)

1. In one sentence, what does a sandbox's network policy check, and what does it miss?
2. What does `[PII_SSN_1]` replace, and when does the real value come back?
3. Name the three detection layers. Which one sends text off the machine?
4. What is a validator? Give two examples.
5. What does "fail closed" mean in piiguard?
6. Name the four steps of the learning loop.
7. How do the threshold gate and the statistical gate differ? Which is safer, and what does it cost?
8. Why was the original 30-attack test set misleading?
9. What is the leak rate of the learned rules on brand-new values? What was it before learning?
10. What happened when spelled-out digits were left out of training? What does that tell you?
11. Why did hex "transfer" even when left out of training?
12. On what kind of PII does Presidio still win?
13. How can a company adopt piiguard without replacing Presidio or NeMo Guardrails?
14. What is the single biggest remaining weakness of the evaluation?

<details><summary>Answers</summary>

1. Host, port and path. It never reads the message body.
2. The SSN. It comes back when the reply returns through the proxy.
3. Pattern rules, local detector, remote classifier. Only the remote classifier sends text off the machine.
4. An extra check on a regex match: the Luhn card checksum; decode as base64 or hex and re-check with the plain rules.
5. If scanning a string takes too long, the whole string is withheld instead of sent unchecked.
6. Red team, test, coach, gate (then commit or revert).
7. The threshold gate uses a fixed 5-point drop. The statistical gate needs a significant paired improvement and no
   new false alarms on 1,075 samples. The statistical gate is safer but learns more slowly.
8. 29 of 30 test values also appeared in training, and the carrier templates were shared, so memorizing looked like
   learning.
9. 26% after learning, 76% before.
10. 0 fixed. The loop learns tricks it is shown; it does not invent new defenses.
11. The coach's instructions list a built-in hex decoder, so it can write a hex rule without seeing a hex attack.
12. Names, places and companies (semantic PII).
13. `piiguard export presidio` or `piiguard export guardrails`.
14. There are no human-written attacks yet.

</details>

---

## 8. Where everything lives

| You want | Go to |
|---|---|
| The pitch and every table | `README.md` |
| The full write-up | `docs/report.md` |
| The rules it learned | `guard/rules.yaml`, `git diff gen-0 gen-23 -- guard/` |
| Every experiment's raw numbers | `runs/*.json` |
| How to reproduce each result | the "Reproducing" section of `docs/report.md` |
| Kit for friends to attack it | `data/attacks-human/README.md` |
