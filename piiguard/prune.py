"""Unlearning, the honest version: drop any rule whose removal changes neither the leak rate nor the
false-positive rate on the validation and clean sets. Rules accumulate across generations; some get
subsumed by later ones, and a dead rule is attack surface and latency for nothing."""
from __future__ import annotations

from dataclasses import dataclass, field

import yaml

from .coach.retrospective import rules_to_yaml
from .eval.harness import evaluate_attacks, evaluate_clean
from .pii.guard import Guard


@dataclass
class PruneResult:
    kept: list[dict]
    dropped: list[str]
    rules_yaml: str
    leak_before: float
    leak_after: float
    fp_before: float
    fp_after: float
    notes: list[str] = field(default_factory=list)


def _scores(rules: list[dict], version: int, attacks: list[dict], clean: list[str]) -> tuple[float, float]:
    g = Guard.from_texts(rules_to_yaml(rules, version))
    _, a = evaluate_attacks(g, attacks)
    _, c = evaluate_clean(g, clean)
    return a["leak_rate"], c["fp_rate"]


def prune_rules(rules_yaml: str, attacks: list[dict], clean: list[str], protect: tuple[str, ...] = ()) -> PruneResult:
    data = yaml.safe_load(rules_yaml)
    version = int(data.get("version", 0))
    rules: list[dict] = [dict(r) for r in data["rules"]]
    leak0, fp0 = _scores(rules, version, attacks, clean)
    dropped: list[str] = []
    notes: list[str] = []
    # Try newest rules first so an older, broader rule is what survives when two overlap.
    for rule in list(reversed(rules)):
        if rule["name"] in protect:
            continue
        trial = [r for r in rules if r is not rule]
        leak, fp = _scores(trial, version, attacks, clean)
        if leak <= leak0 and fp <= fp0:
            rules = trial
            dropped.append(rule["name"])
            notes.append(f"dropped {rule['name']}: no change (leak {leak:.2f}, fp {fp:.2f})")
        else:
            notes.append(f"kept {rule['name']}: removal would move leak {leak0:.2f}->{leak:.2f}, fp {fp0:.2f}->{fp:.2f}")
    leak1, fp1 = _scores(rules, version, attacks, clean)
    return PruneResult(rules, dropped, rules_to_yaml(rules, version), leak0, leak1, fp0, fp1, notes)
