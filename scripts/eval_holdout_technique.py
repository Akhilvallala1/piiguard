"""Leave-one-technique-out: can the loop handle an obfuscation technique it never trained on?

Every committed training and fresh test attack comes from the same 12 Python encoders, so a good fresh-set score could
mean "learned these 12 tricks", not "learned to generalize". This holds a technique out of training entirely, trains
from gen-0 in an isolated clone, and scores only the held-out technique on unseen values. The paired control is the
same technique's leak rate under gen-0 (before any learning).

If the loop only memorizes tricks, leak on the held-out technique should not move. If its rules generalize, it should
drop even though no training attack used that technique.

  PIIGUARD_BUDGET_USD=2 python scripts/eval_holdout_technique.py --techniques reversed,spelled,hex,split_lines
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from ablate_gates import _sh, make_arm, run_arm  # noqa: E402
from piiguard.eval.datasets import load_jsonl  # noqa: E402
from piiguard.eval.scoring import is_leak  # noqa: E402
from piiguard.eval.stats import fmt_rate, mcnemar, paired_counts  # noqa: E402
from piiguard.pii.guard import Guard  # noqa: E402
from piiguard.redteam.encoders import ENCODERS  # noqa: E402
from piiguard.redteam.fresh import generate_fresh  # noqa: E402
from piiguard.redteam.generator import CARRIERS, SEED_PEOPLE  # noqa: E402


def heldout_values() -> set:
    seen = {v for p in SEED_PEOPLE for v in p.values()}
    for d in ("attacks-fresh", "attacks-crossfamily", "attacks-formats"):
        p = ROOT / "data" / d / "heldout.jsonl"
        if p.exists():
            seen |= {a["plain_value"] for a in load_jsonl(p)}
    return seen


def run_one(tech: str, generations: int, base: Path, log) -> dict:
    others = [t for t in ENCODERS if t not in (tech, "plain")] + ["plain"]
    seed = 5150 + list(ENCODERS).index(tech)  # stable across runs (hash() is randomized per process)
    rows = generate_fresh(240, seed=seed, techniques=others, exclude_values=heldout_values(), carriers=CARRIERS)
    assert not any(r["technique"] == tech for r in rows)
    train, val = rows[:180], rows[180:]
    path = make_arm(base, f"without_{tech}", train, val)
    run_arm(path, dict(gate="threshold", memory=True, clean="small"), generations, log)
    test = [a for a in load_jsonl(ROOT / "data/attacks-fresh/heldout.jsonl") if a["technique"] == tech]
    g0 = Guard.from_texts(_sh("git", "show", "gen-0:guard/rules.yaml", cwd=ROOT))
    gN = Guard.from_dir(path / "guard")
    before = [is_leak(g0.redact(a["text"]).text, a["surface_forms"]) for a in test]
    after = [is_leak(gN.redact(a["text"]).text, a["surface_forms"]) for a in test]
    # control: the same arm on the techniques it DID train on, so we can compare transfer to direct learning
    trained = [a for a in load_jsonl(ROOT / "data/attacks-fresh/heldout.jsonl") if a["technique"] != tech]
    tb = [is_leak(g0.redact(a["text"]).text, a["surface_forms"]) for a in trained]
    ta = [is_leak(gN.redact(a["text"]).text, a["surface_forms"]) for a in trained]
    fixed, broken = paired_counts(before, after)
    tf, tbk = paired_counts(tb, ta)
    hist = path / "runs" / "history.jsonl"
    recs = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()] if hist.exists() else []
    spend = [l for l in (path / "runs" / "ablation.log").read_text().splitlines() if l.startswith("[spend]")]
    return {"technique": tech, "n": len(test), "before": sum(before), "after": sum(after), "fixed": fixed, "broken": broken,
            "p": mcnemar(fixed, broken), "trained_n": len(trained), "trained_before": sum(tb), "trained_after": sum(ta),
            "trained_fixed": tf, "trained_broken": tbk, "accepted": sum(r["accepted"] for r in recs), "generations": len(recs),
            "spend": spend[-1][8:] if spend else "n/a"}


def render(rows: list[dict]) -> str:
    lines = ["| held-out technique | its leak, gen-0 | its leak after training without it | fixed / broke | p | "
             "trained techniques, gen-0 to after |", "|---|---|---|---|---|---|"]
    for r in rows:
        p = "<0.001" if r["p"] < 0.001 else f"{r['p']:.3f}"
        lines.append(f"| {r['technique']} | {fmt_rate(r['before'], r['n'])} | {fmt_rate(r['after'], r['n'])} | "
                     f"{r['fixed']} / {r['broken']} | {p} | {r['trained_before'] / r['trained_n']:.0%} to {r['trained_after'] / r['trained_n']:.0%} |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--techniques", default="reversed,spelled,hex,split_lines")
    ap.add_argument("--generations", type=int, default=6)
    a = ap.parse_args()
    techs = [t.strip() for t in a.techniques.split(",")]
    unknown = [t for t in techs if t not in ENCODERS]
    if unknown:
        raise SystemExit(f"unknown techniques: {unknown}; choose from {list(ENCODERS)}")
    base = ROOT.parent / "ablation-holdout"
    base.mkdir(exist_ok=True)
    log = lambda s: print(s, file=sys.stderr, flush=True)
    with ThreadPoolExecutor(len(techs)) as ex:
        rows = list(ex.map(lambda t: run_one(t, a.generations, base, log), techs))
    (ROOT / "runs" / "holdout-technique.json").write_text(json.dumps(rows, indent=2))
    print(render(rows))
    for r in rows:
        log(f"{r['technique']}: {r['accepted']}/{r['generations']} accepted, {r['spend']}")


if __name__ == "__main__":
    main()
