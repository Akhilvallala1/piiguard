"""The hook for the demo: the SAME agent request, sent two ways.

1. DIRECT  - what an agent inside a NemoClaw sandbox with a normal egress policy sends to Crusoe / You.com.
             OpenShell allows it: the hosts are on the allow-list. The SSN leaves the machine.
2. GUARDED - the same request through the piiguard proxy. The SSN never leaves; the agent still gets its answer.

Usage: piiguard serve --port 8787   (in another terminal)
       python scripts/demo_leak.py [--live]   (--live actually calls Crusoe/You.com; default prints the payloads)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import httpx

RECORD = {"name": "Maria Chen", "ssn": "912-34-5678", "email": "maria.chen@example.com", "card": "4111 1111 1111 1111"}
TASK = (f"Customer {RECORD['name']} (SSN {RECORD['ssn']}, email {RECORD['email']}, card {RECORD['card']}) "
        "is asking whether her card is eligible for the 2026 cashback program. Draft a two-sentence reply.")
SEARCH = f"is card {RECORD['card']} eligible for cashback {RECORD['name']}"


def banner(s):
    print("\n" + "=" * 78 + f"\n{s}\n" + "=" * 78)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--proxy", default="http://127.0.0.1:8787")
    a = ap.parse_args()
    token = os.environ.get("GUARD_PROXY_TOKEN") or sys.exit("set GUARD_PROXY_TOKEN to the token the proxy printed")
    payload = {"model": os.environ.get("WORKER_MODEL", "nvidia/Nemotron-3.5-Lightning-30B-A3B"),
               "messages": [{"role": "user", "content": TASK}], "max_tokens": 900}

    banner("1. DIRECT: agent -> Crusoe / You.com (sandbox policy allows these hosts)")
    print("POST https://api.inference.crusoecloud.com/v1/chat/completions")
    print(json.dumps(payload, indent=2))
    print("GET  https://api.you.com/v1/search?query=" + SEARCH)
    leaked = [v for v in RECORD.values() if v in json.dumps(payload) or v in SEARCH]
    print(f"\n  >>> {len(leaked)} PII values left the machine: {leaked}")

    banner("2. GUARDED: agent -> piiguard proxy -> Crusoe / You.com")
    if not a.live:
        from piiguard.pii.guard import Guard
        g = Guard.from_dir(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "guard"))
        red = g.redact(TASK)
        print("what actually leaves the host:\n  " + red.text)
        print("\nwhat the agent gets back (restored):\n  " + g.restore(red.text, red.mapping)[:120] + " ...")
        print(f"\n  >>> 0 PII values left the machine; {len(red.mapping)} tokens held on host: {list(red.mapping)}")
        print("\n(run with --live and `piiguard serve` to do it for real)")
        return
    h = {"Authorization": f"Bearer {token}"}
    r = httpx.post(f"{a.proxy}/v1/chat/completions", json=payload, headers=h, timeout=120)
    msg = r.json()["choices"][0]["message"]
    answer = msg.get("content") or f"(model spent its budget reasoning; reasoning starts: {str(msg.get('reasoning', ''))[:120]!r})"
    print("agent received:", answer[:300])
    ev = httpx.get(f"{a.proxy}/events", headers=h).json()[-1]
    print("\nguard event:", json.dumps(ev, indent=2))
    print(f"\n  >>> what left the host: {ev['preview']}")
    s = httpx.get(f"{a.proxy}/you/search", params={"q": SEARCH}, headers=h, timeout=60)
    ev2 = httpx.get(f"{a.proxy}/events", headers=h).json()[-1]
    print("\nsearch query that left the host:", ev2["preview"])
    print("search status:", s.status_code)


if __name__ == "__main__":
    sys.exit(main())
