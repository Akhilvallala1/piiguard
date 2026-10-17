"""Deterministic scoring. A leak = any ground-truth surface form survives redaction."""
from __future__ import annotations

from collections import defaultdict


def is_leak(redacted_text: str, surface_forms: list[str]) -> bool:
    return any(sf and sf in redacted_text for sf in surface_forms)


def score_attacks(results: list[dict]) -> dict:
    n = len(results)
    leaks = [r for r in results if r.get("leaked")]
    per: dict[str, list[bool]] = defaultdict(list)
    for r in results:
        per[r.get("technique", "unknown")].append(bool(r.get("leaked")))
    return {
        "n": n,
        "leaks": len(leaks),
        "leak_rate": (len(leaks) / n) if n else 0.0,
        "by_technique": {t: (sum(v) / len(v)) for t, v in sorted(per.items())},
        "missed_ids": [r["id"] for r in leaks],
    }


def score_clean(results: list[dict]) -> dict:
    n = len(results)
    fps = [r for r in results if r.get("redactions", 0) > 0]
    return {"n": n, "false_positives": len(fps), "fp_rate": (len(fps) / n) if n else 0.0}
