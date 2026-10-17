# Demo script (3 minutes live, 1 minute video)

## 0:00 The opening (20 s): PII depends on the industry
Say, before touching the keyboard:
"What counts as PII depends on where you work. An adjuster badge number means nothing to you. Inside an insurance company
it unlocks a claim file. A claim number, a policy number, a member ID, a case number: every industry has its own.
No static detector ships with your identifiers. Microsoft Presidio has recognizers for emails and phone numbers and
nothing for an adjuster badge. So the question is not 'which PII detector do we buy'. It is 'can the guard learn ours'."
The page has an Industry row: Insurance claim, Healthcare, Finance, Law firm, General. Each one loads a realistic prompt,
tells the classifier the domain, adds that domain's seed rules, and grades every pane against the domain's ground truth
(the line under the buttons says what counts as PII there). Click Insurance claim and Send.
Numbers to say: on the insurance red team, hand-written rules leaked 90% of held-out attacks; after generations 22 and 23
the coach's rules leak 20%, false positives still 0%. The general held-out stayed at 16.7%: learning insurance did not
cost anything elsewhere. Three panes: everything leaves; Presidio catches the phone and the
name and walks past the badge and the claim; piiguard catches them, because its red team speaks insurance and its coach
wrote the rules. Point at the egress log: that is what actually left this laptop.

## 0:20 The hook (30 s)
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

"Hand-written rules caught 23 percent of our red-team attacks (held-out leak rate 76.7%). Then we let the system fight itself:
a Nemotron Super red team encodes PII twelve different ways inside search queries, tool calls, logs and
code; a Nemotron Super coach reads every attack that leaked and rewrites the regex rules and the
classifier prompt; a gate keeps a change only if the validation leak rate drops and false positives on
clean traffic do not rise. Every accepted change is a git tag."
Point at the held-out line: `76.7% -> 16.7%` on attacks the coach never saw, false positives 0% -> 0%.
With the Nemotron 3.5 Lightning classifier behind the rules: 0% leak, 0% false positives, ~3 s/request.
Presidio on the same data: 53.3% leak with 64% false positives (default), 70% leak with 4% FP (scoped).

## 2:00 Show the learning (40 s)
`git diff gen-0 gen-3 -- guard/rules.yaml` -> one accepted rule, plain English rationale in the commit.
`piiguard report` row with `n` -> a rejected proposal and why (false positives rose / no gain).

## 2:40 Sandbox tie-in (20 s)
Live NemoClaw sandbox `piiguard-agent` (OpenClaw, OpenShell 0.0.116). Its only inference route is the guard proxy:

```bash
# from inside the sandbox: the agent thinks it is talking to a normal OpenAI endpoint
nemoclaw piiguard-agent exec -- sh -c 'curl -sk https://inference.local/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"nvidia/Nemotron-3.5-Lightning-30B-A3B\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply OK. Customer SSN 912-34-5678\"}],\"max_tokens\":200}"'
# on the host: what actually left the machine
tail -1 runs/proxy-events.jsonl
#  -> "preview": "Reply OK. Customer SSN [PII_SSN_1]"
```

`nemoclaw piiguard-agent status` shows Provider: compatible-endpoint -> http://host.openshell.internal:8787/v1.
The Crusoe key lives only in the proxy; the sandbox holds a proxy token.
"NemoClaw decides where. piiguard decides what. Together you can actually walk away."

## Setup notes (for the README / Q&A)
- Installer bug on nvm-managed Node: it rejects the shims it just wrote. Workaround: move `~/.local/bin/nemoclaw*` aside and run `nemoclaw onboard` directly.
- OpenShell routes a custom endpoint literally; `127.0.0.1` is the sandbox's loopback. Use `http://host.openshell.internal:8787/v1`
  (`openshell provider update compatible-endpoint --config OPENAI_BASE_URL=...` if it was created with the wrong URL).

## Q&A ammo
- "Isn't the classifier expensive?" Only paid for when the text earns it. A router scores what the regex rules left behind and
  picks skip / Nemotron 3.5 Lightning (~1 s) / Nemotron 3 Super (~2 s). The page prints the route per request. The policy is one
  pure function; NVIDIA NeMo Switchyard's stage_router is the production home for it.
- "Why not just use Presidio?" It is on the page, live, on the judge's own prompt. It has no recognizer for an adjuster badge or a
  claim number, and it flags dates and places as PII on clean traffic. A static detector stays where it is.
- "Your phone rule missed parenthesized numbers." Yes, that was the hand-written gen-0 rule, and the one human hotfix in the history.
  Every other rule change was proposed by the coach and accepted by the gate.
- "Can it unlearn?" Yes, two ways. Rollback is a git tag away. And `piiguard prune` ablates every rule and drops it only if
  nothing changes on train+val; held-out is a tripwire. Live: it found 10 "dead" rules and refused, because held-out leak
  would have gone 16.7% -> 26.7%. A guard should only forget when forgetting is provably free.
- Why not just a bigger model? The guard runs on a 3B-active Nemotron; the coach is expensive but runs offline.
- Held-out set is never shown to the coach; split is seeded and committed.
- Reversible tokens mean the agent's task still completes; nothing is lost, only moved.
- False positives are measured on 25 number-heavy hard negatives (timestamps, versions, order ids).
- Regex from an LLM is untrusted: length cap, nested-quantifier rejection, probe timing before acceptance.
- Everything was written today; the author's earlier guardrail project inspired the design, no code reused.
