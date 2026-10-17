"""One generation of self-improvement: eval -> coach -> stage -> gate -> commit or revert."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable, Optional

from .coach.gate import GuardRepo, decide
from .coach.retrospective import Proposal
from .eval.harness import evaluate_attacks, evaluate_clean
from .pii.guard import Classifier, Guard

CoachFn = Callable[[list[dict], str, str, dict], Proposal]


def _scores(guard: Guard, attacks: list[dict], clean: list[str]) -> tuple[dict, dict]:
    _, a = evaluate_attacks(guard, attacks)
    _, c = evaluate_clean(guard, clean)
    return a, c


def run_generation(root: str | Path, gen: int, train: list[dict], val: list[dict], clean: list[str], coach_fn: CoachFn,
                   classifier: Optional[Classifier] = None, min_leak_delta: float = 0.05, max_fp_increase: float = 0.05,
                   log: Callable[[str], None] = lambda s: None) -> dict:
    root = Path(root)
    repo = GuardRepo(root)
    t0 = time.time()

    guard = Guard.from_dir(repo.guard_dir, classifier)
    train_results, train_scores = evaluate_attacks(guard, train)
    missed = set(train_scores["missed_ids"])
    misses = [a for a in train if a["id"] in missed]
    val_before, clean_before = _scores(guard, val, clean)
    log(f"[gen {gen}] train leak {train_scores['leak_rate']:.2f} | val leak {val_before['leak_rate']:.2f} | fp {clean_before['fp_rate']:.2f} | {len(misses)} misses -> coach")

    rules_yaml, prompt_md = repo.current_files()
    try:
        proposal = coach_fn(misses, rules_yaml, prompt_md, train_scores)
    except Exception as e:  # noqa: BLE001 - a bad coach turn is a rejected generation, not a crash
        reason = f"rejected: coach failed to produce a valid proposal ({type(e).__name__}: {str(e)[:160]})"
        log(f"[gen {gen}] {reason}")
        record = {"gen": gen, "accepted": False, "reason": reason, "commit": None, "rationale": "", "n_misses": len(misses),
                  "train_before": train_scores, "val_before": val_before, "val_after": val_before,
                  "fp_before": clean_before, "fp_after": clean_before, "proposal": None,
                  "seconds": round(time.time() - t0, 1), "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
        _append_history(root, record)
        return record
    log(f"[gen {gen}] coach: {proposal.rationale}")

    repo.stage(_stamp_version(proposal.rules_yaml, gen), proposal.prompt_md if proposal.prompt_md is not None else prompt_md)
    candidate = Guard.from_dir(repo.guard_dir, classifier)
    val_after, clean_after = _scores(candidate, val, clean)
    fp_examples = _fp_examples(candidate, clean)
    decision = decide({"leak_rate": val_before["leak_rate"], "fp_rate": clean_before["fp_rate"]},
                      {"leak_rate": val_after["leak_rate"], "fp_rate": clean_after["fp_rate"]},
                      min_leak_delta, max_fp_increase)
    sha = None
    if decision.accepted:
        sha = repo.commit(f"gen-{gen}", f"gen {gen}: {proposal.rationale}\n\nval leak {val_before['leak_rate']:.2f} -> {val_after['leak_rate']:.2f}, fp {clean_before['fp_rate']:.2f} -> {clean_after['fp_rate']:.2f}")
    else:
        repo.revert()
    log(f"[gen {gen}] {decision.reason}" + (f" (commit {sha})" if sha else ""))

    record = {
        "gen": gen, "accepted": decision.accepted, "reason": decision.reason, "commit": sha,
        "rationale": proposal.rationale, "n_misses": len(misses),
        "train_before": train_scores, "val_before": val_before, "val_after": val_after,
        "fp_before": clean_before, "fp_after": clean_after, "fp_examples": fp_examples,
        "proposal": {"rules_yaml": proposal.rules_yaml, "prompt_md": proposal.prompt_md},
        "seconds": round(time.time() - t0, 1), "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    _append_history(root, record)
    return record


def _stamp_version(rules_yaml: str, gen: int) -> str:
    """The rules file's version is the generation that produced it (coach output always says 0)."""
    import re
    stamped, n = re.subn(r"^'?version'?:.*$", f"version: {gen}", rules_yaml, count=1, flags=re.M)
    return stamped if n else f"version: {gen}\n" + rules_yaml


def _fp_examples(guard: Guard, clean: list[str], limit: int = 8) -> list[dict]:
    """Which clean samples a candidate guard flags, and by which rule: the most useful feedback the coach can get."""
    out = []
    for text in clean:
        red = guard.redact(text)
        for f in red.findings:
            out.append({"rule": f.type, "text": text, "value": text[f.start:f.end]})
            break
        if len(out) >= limit:
            break
    return out


def _append_history(root: Path, record: dict) -> None:
    runs = root / "runs"
    runs.mkdir(exist_ok=True)
    with (runs / "history.jsonl").open("a") as f:
        f.write(json.dumps(record) + "\n")
