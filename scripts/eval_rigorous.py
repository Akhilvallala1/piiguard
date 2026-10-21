"""Rigorous evaluation: fresh-value attacks (n=500) and a 1,075-sample clean corpus, with 95% Wilson intervals,
strict and any-leak rates, and paired McNemar tests against the current rules.

  python scripts/eval_rigorous.py            # local systems only, no API calls
  RIGOR_LLM=1 python scripts/eval_rigorous.py  # also the remote Nemotron classifier (spends Crusoe credits)

Writes runs/rigorous.json and prints a markdown table."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiguard.bench import presidio_redactor  # noqa: E402
from piiguard.cli import _classifier  # noqa: E402
from piiguard.coach.gate import GuardRepo  # noqa: E402
from piiguard.eval.clean_corpus import generate_clean  # noqa: E402
from piiguard.eval.datasets import load_jsonl  # noqa: E402
from piiguard.eval.harness import CLEAN_SAMPLES  # noqa: E402
from piiguard.eval.scoring import is_leak, leak_kind  # noqa: E402
from piiguard.eval.stats import fmt_rate, mcnemar, paired_counts  # noqa: E402
from piiguard.pii.guard import Guard  # noqa: E402


def run(fn, attacks, clean):
    t0 = time.perf_counter()
    reds = [fn(a["text"]) for a in attacks]
    strict = [is_leak(r, a["surface_forms"]) for a, r in zip(attacks, reds)]
    anyl = [leak_kind(r, a["surface_forms"], a.get("plain_value")) != "none" for a, r in zip(attacks, reds)]
    fp = [fn(t) != t for t in clean]
    ms = 1000 * (time.perf_counter() - t0) / (len(attacks) + len(clean))
    return {"strict": strict, "any": anyl, "fp": fp, "ms": round(ms, 1)}


def main():
    which = os.environ.get("RIGOR_SET", "fresh")
    path = {"fresh": "attacks-fresh", "crossfamily": "attacks-crossfamily"}[which]
    attacks = load_jsonl(ROOT / "data" / path / "heldout.jsonl")
    clean = list(CLEAN_SAMPLES) + generate_clean()
    g0 = Guard.from_texts(*GuardRepo(ROOT).files_at("gen-0"))
    gn = Guard.from_dir(ROOT / "guard")
    pres = presidio_redactor()
    pres_scoped = presidio_redactor(entities=["US_SSN", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"])
    systems = {
        "Microsoft Presidio (default recognizers)": pres,
        "Microsoft Presidio (scoped: SSN, email, phone, card)": pres_scoped,
        "piiguard gen-0 rules (hand-written)": lambda t: g0.redact(t).text,
        f"piiguard gen-{gn.rules.version} rules (learned, no model)": lambda t: gn.redact(t).text,
    }
    for d in ("presidio", "gliner"):
        gd = Guard.from_dir(ROOT / "guard", _classifier(False, d))
        systems[f"piiguard gen-{gn.rules.version} rules + local {d}"] = lambda t, g=gd: g.redact(t).text
    if os.environ.get("RIGOR_LLM"):
        gl = Guard.from_dir(ROOT / "guard", _classifier(True))
        systems[f"piiguard gen-{gn.rules.version} rules + remote Nemotron"] = lambda t, g=gl: g.redact(t).text

    ref_name = f"piiguard gen-{gn.rules.version} rules (learned, no model)"
    results = {}
    for name, fn in systems.items():
        print(f"running {name} ...", file=sys.stderr, flush=True)
        results[name] = run(fn, attacks, clean)
    out = {"set": which, "n_attacks": len(attacks), "n_clean": len(clean), "reference": ref_name, "systems": {}}
    for name, r in results.items():
        ref = results[ref_name]
        fixed, broken = paired_counts(ref["strict"], r["strict"])
        out["systems"][name] = {
            "strict_leaks": sum(r["strict"]), "any_leaks": sum(r["any"]), "fps": sum(r["fp"]), "ms": r["ms"],
            "vs_reference": {"fixed": fixed, "broken": broken, "p_better": mcnemar(fixed, broken), "p_worse": mcnemar(broken, fixed)},
        }
    # gen-0 -> learned rules: the loop's own claim, now on data it never saw
    f, b = paired_counts(results["piiguard gen-0 rules (hand-written)"]["strict"], results[ref_name]["strict"])
    out["learning_effect"] = {"fixed": f, "broken": b, "p": mcnemar(f, b)}
    by_tech = {}
    for name, r in results.items():
        agg = {}
        for a, leaked in zip(attacks, r["strict"]):
            t = "freeform (model's own technique)" if a["technique"].startswith("freeform") else "known encoder"
            agg.setdefault(t, [0, 0])
            agg[t][0] += leaked
            agg[t][1] += 1
        by_tech[name] = agg
    out["by_origin"] = by_tech
    (ROOT / "runs").mkdir(exist_ok=True)
    suffix = "" if which == "fresh" else f"-{which}"
    (ROOT / "runs" / f"rigorous{suffix}.json").write_text(json.dumps(out, indent=2))
    print(render(out))
    try:
        from piiguard.crusoe import METER
        print(METER.summary(), file=sys.stderr)
    except Exception:  # noqa: BLE001
        pass


def _p(p: float) -> str:
    return "<0.001" if p < 0.001 else f"{p:.3f}"


def render(out: dict) -> str:
    n, m = out["n_attacks"], out["n_clean"]
    lines = [f"| system | strict leak (n={n}) | any leak, incl. partial | false positives (n={m}) | ms/text |", "|---|---|---|---|---|"]
    for name, s in out["systems"].items():
        lines.append(f"| {name} | {fmt_rate(s['strict_leaks'], n)} | {fmt_rate(s['any_leaks'], n)} | {fmt_rate(s['fps'], m)} | {s['ms']:.0f} |")
    le = out["learning_effect"]
    lines.append(f"\nLearning effect, gen-0 to learned rules, on these unseen values: fixed {le['fixed']}, broke {le['broken']}, "
                 f"one-sided exact McNemar p {_p(le['p'])}. Brackets are 95% Wilson intervals.")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
