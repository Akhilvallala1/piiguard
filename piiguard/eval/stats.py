"""Small-sample statistics for leak and false-positive rates. Pure Python, no scipy.

* ``wilson`` gives a 95% interval for a proportion; it behaves at 0 and n (unlike the normal approximation), which
  matters when a guard leaks 0 of 30.
* ``mcnemar`` is the exact paired test for "did the candidate leak on fewer of the same attacks than the incumbent":
  only discordant pairs (one leaked, the other did not) carry information.
"""
from __future__ import annotations

import math

Z95 = 1.959963984540054


def wilson(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    if n <= 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    lo, hi = max(0.0, centre - half), min(1.0, centre + half)
    return (0.0 if k == 0 else lo, 1.0 if k == n else hi)


def fmt_rate(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{k / n:.1%} [{lo:.1%}, {hi:.1%}]" if n else "n/a"


def _binom_tail_le(k: int, n: int) -> float:
    """P(X <= k) for X ~ Binomial(n, 0.5)."""
    return sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)


def mcnemar(fixed: int, broken: int) -> float:
    """One-sided exact McNemar p-value that the candidate is better.

    fixed:  attacks the incumbent leaked and the candidate caught
    broken: attacks the incumbent caught and the candidate leaked
    """
    n = fixed + broken
    if n == 0:
        return 1.0
    return _binom_tail_le(broken, n)


def paired_counts(before: list[bool], after: list[bool]) -> tuple[int, int]:
    """(fixed, broken) from per-item leak flags in the same order."""
    if len(before) != len(after):
        raise ValueError("paired outcomes must be the same length and order")
    fixed = sum(1 for b, a in zip(before, after) if b and not a)
    broken = sum(1 for b, a in zip(before, after) if a and not b)
    return fixed, broken
