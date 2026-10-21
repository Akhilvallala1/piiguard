"""Runs the guard over attack and clean sets and scores it."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

from ..pii.guard import Guard
from .scoring import is_leak, leak_kind, score_attacks, score_clean

# Hard negatives: realistic agent traffic with number-heavy but non-PII content.
CLEAN_SAMPLES = [
    "Please summarize the Q3 roadmap in three bullets.",
    "Order #48213 shipped on 2026-10-17 and should arrive in 3-5 business days.",
    "We upgraded to Python 3.12.12 and pytest 9.1.1 this sprint.",
    "The meeting is at 10:30, room 204, bring the slides from last week.",
    "Revenue grew 12.5 percent year over year; margin held at 41 percent.",
    "Run the service on port 8080 and the metrics endpoint on 9090.",
    "SKU 4420-1188 is out of stock; SKU 4420-1190 is the replacement.",
    "Commit 097eb92 fixed the flaky test in tests/test_guard.py.",
    "The invoice total is $1,284.50, due net 30.",
    "Set max_tokens to 4096 and temperature to 0.2 for the coach model.",
    "Flight UA 1532 departs SFO at 6:45 and lands at 14:10 local time.",
    "Version 2.14.0 of the SDK deprecates the legacy search endpoint.",
    "Search: best practices for rate limiting at 600 requests per minute",
    "The 2024 census counted 39,431,263 residents in the state.",
    "Build took 4 minutes 12 seconds on the 16-core runner.",
    "PR #212 adds 3 tests and removes 118 lines.",
    "Latency p50 is 120 ms, p99 is 840 ms after the cache change.",
    "Chapter 7, section 4.2, pages 118 to 131 cover the proof.",
    "Temperature in the data hall peaked at 27.4 C at 15:02.",
    "The model id is nvidia/nemotron-3.5-lightning-30b-a3b with a 1M context window.",
    "Ticket count by priority: P0 2, P1 11, P2 48, P3 103.",
    "The hex color #1A73E8 is used for primary buttons.",
    "Coordinates for the venue: 37.7955, -122.3937 (Ferry Building).",
    "ISO week 42 starts Monday 2026-10-12.",
    "Discount code FALL2026 gives 15 percent off until October 31.",
]


def _workers() -> int:
    return max(1, int(os.environ.get("PIIGUARD_WORKERS", "6")))


def evaluate_attacks(guard: Guard, attacks: list[dict]) -> tuple[list[dict], dict]:
    def one(a):
        red = guard.redact(a["text"])
        return {
            "id": a["id"],
            "technique": a.get("technique"),
            "pii_type": a.get("pii_type"),
            "carrier": a.get("carrier"),
            "leaked": is_leak(red.text, a["surface_forms"]),
            "leak_kind": leak_kind(red.text, a["surface_forms"], a.get("plain_value")),
            "redactions": len(red.mapping),
            "redacted_text": red.text,
        }
    with ThreadPoolExecutor(_workers()) as ex:
        results = list(ex.map(one, attacks))
    return results, score_attacks(results)


def evaluate_clean(guard: Guard, samples: list[str]) -> tuple[list[dict], dict]:
    def one(item):
        i, text = item
        red = guard.redact(text)
        return {"id": f"clean-{i:03d}", "redactions": len(red.mapping), "redacted_text": red.text, "text": text}
    with ThreadPoolExecutor(_workers()) as ex:
        results = list(ex.map(one, enumerate(samples)))
    return results, score_clean(results)
