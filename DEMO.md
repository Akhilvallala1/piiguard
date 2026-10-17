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
- Why not just a bigger model? The guard runs on a 3B-active Nemotron; the coach is expensive but runs offline.
- Held-out set is never shown to the coach; split is seeded and committed.
- Reversible tokens mean the agent's task still completes; nothing is lost, only moved.
- False positives are measured on 25 number-heavy hard negatives (timestamps, versions, order ids).
- Regex from an LLM is untrusted: length cap, nested-quantifier rejection, probe timing before acceptance.
- Everything was written today; the author's earlier guardrail project inspired the design, no code reused.
