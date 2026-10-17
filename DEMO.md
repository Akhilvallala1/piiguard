# Demo script (3 minutes live, 1 minute video)

## 0:00 The hook (30 s)
Terminal 1: `piiguard serve --host 0.0.0.0 --port 8787 --llm` is already running.
Terminal 2: `python scripts/demo_leak.py`

"This is a NemoClaw sandbox with a normal egress policy: Crusoe allowed, You.com allowed.
The agent gets a customer ticket. Here is what it sends out." -> point at the SSN and card number in the
search query and the prompt. "OpenShell allowed every byte, because it checks hosts, not content.
That is not a bug in NemoClaw. It is a missing layer. We built the layer, and made it train itself."

## 0:30 The guard (30 s)
Same script, second half: the same request through the proxy. Tokens leave, values stay, agent still gets
its answer back with the real values restored. Show `/events`: one line per request, what left the host.

## 1:00 Generation 0 vs generation N (60 s)
`piiguard report`

"Hand-written rules caught 23 percent of our red-team attacks. Then we let the system fight itself:
a Nemotron Super red team encodes PII twelve different ways inside search queries, tool calls, logs and
code; a Nemotron Super coach reads every attack that leaked and rewrites the regex rules and the
classifier prompt; a gate keeps a change only if the validation leak rate drops and false positives on
clean traffic do not rise. Every accepted change is a git tag."
Point at the held-out line: `X% -> Y%` on attacks the coach never saw.

## 2:00 Show the learning (40 s)
`git diff gen-0 gen-3 -- guard/rules.yaml` -> one accepted rule, plain English rationale in the commit.
`piiguard report` row with `n` -> a rejected proposal and why (false positives rose / no gain).

## 2:40 Sandbox tie-in (20 s)
`cat nemoclaw/piiguard-egress.yaml` -> the sandbox's only route is the guard; keys never enter the sandbox.
"NemoClaw decides where. piiguard decides what. Together you can actually walk away."

## Q&A ammo
- Why not just a bigger model? The guard runs on a 3B-active Nemotron; the coach is expensive but runs offline.
- Held-out set is never shown to the coach; split is seeded and committed.
- Reversible tokens mean the agent's task still completes; nothing is lost, only moved.
- False positives are measured on 25 number-heavy hard negatives (timestamps, versions, order ids).
- Regex from an LLM is untrusted: length cap, nested-quantifier rejection, probe timing before acceptance.
- Everything was written today; the author's earlier guardrail project inspired the design, no code reused.
