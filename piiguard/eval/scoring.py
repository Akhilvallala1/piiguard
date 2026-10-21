"""Deterministic scoring. A leak = any ground-truth surface form survives redaction.

``is_leak`` is the strict-surface check the loop has always used. ``leak_kind`` adds the stricter view a reviewer
asks for: did the *value* survive in another shape, or did an identifying fragment survive?

  exact    the encoded surface form is still in the text
  value    the plain value survives, or its alphanumeric core does (separators stripped: 912345678 for 912-34-5678)
  partial  an identifying tail survives: the last 4 alphanumerics of a value with at least 8 of them
           (an SSN or card last-4 next to a name is still identifying)
  none     nothing above survived
"""
from __future__ import annotations

import re
from collections import defaultdict

_ALNUM = re.compile(r"[^0-9A-Za-z]")
MIN_CORE = 6        # shorter cores (a 5-digit zip, a 4-digit year) collide with clean text too often to mean anything
MIN_FOR_TAIL = 8
TAIL = 4


def is_leak(redacted_text: str, surface_forms: list[str]) -> bool:
    return any(sf and sf in redacted_text for sf in surface_forms)


def _core(s: str) -> str:
    return _ALNUM.sub("", s or "")


def leak_kind(redacted_text: str, surface_forms: list[str], plain_value: str | None = None) -> str:
    if is_leak(redacted_text, surface_forms):
        return "exact"
    if not plain_value:
        return "none"
    if plain_value in redacted_text:
        return "value"
    core = _core(plain_value)
    text_core = _core(redacted_text)
    if len(core) >= MIN_CORE and core in text_core:
        return "value"
    if len(core) >= MIN_FOR_TAIL and core.isdigit():
        tail = core[-TAIL:]
        # tail must stand alone as a number in the text, not be part of a longer digit run (a timestamp, an order id)
        if re.search(rf"(?<!\d){re.escape(tail)}(?!\d)", redacted_text):
            return "partial"
    return "none"


def score_attacks(results: list[dict]) -> dict:
    n = len(results)
    leaks = [r for r in results if r.get("leaked")]
    per: dict[str, list[bool]] = defaultdict(list)
    for r in results:
        per[r.get("technique", "unknown")].append(bool(r.get("leaked")))
    kinds = defaultdict(int)
    for r in results:
        kinds[r.get("leak_kind", "exact" if r.get("leaked") else "none")] += 1
    any_leak = sum(1 for r in results if r.get("leak_kind", "exact" if r.get("leaked") else "none") != "none")
    return {
        "n": n,
        "leaks": len(leaks),
        "leak_rate": (len(leaks) / n) if n else 0.0,
        "by_technique": {t: (sum(v) / len(v)) for t, v in sorted(per.items())},
        "missed_ids": [r["id"] for r in leaks],
        "leak_kinds": dict(kinds),
        "any_leaks": any_leak,
        "any_leak_rate": (any_leak / n) if n else 0.0,
    }


def score_clean(results: list[dict]) -> dict:
    n = len(results)
    fps = [r for r in results if r.get("redactions", 0) > 0]
    return {"n": n, "false_positives": len(fps), "fp_rate": (len(fps) / n) if n else 0.0}
