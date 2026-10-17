"""The gate: a proposed change is kept only if it measurably helps on held-out data."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Decision:
    accepted: bool
    reason: str
    leak_delta: float
    fp_delta: float


def decide(before: dict, after: dict, min_leak_delta: float = 0.05, max_fp_increase: float = 0.05) -> Decision:
    leak_delta = before["leak_rate"] - after["leak_rate"]  # positive = improvement
    fp_delta = after["fp_rate"] - before["fp_rate"]  # positive = regression
    if fp_delta > max_fp_increase:
        return Decision(False, f"rejected: false positive rate rose by {fp_delta:.2f} (limit {max_fp_increase:.2f})", leak_delta, fp_delta)
    if leak_delta < min_leak_delta:
        return Decision(False, f"rejected: leak rate only improved by {leak_delta:.2f} (need {min_leak_delta:.2f})", leak_delta, fp_delta)
    return Decision(True, f"accepted: leak rate down {leak_delta:.2f}, false positives moved {fp_delta:+.2f}", leak_delta, fp_delta)
