"""Unseen identifier formats: does the guard handle ID *formats* it was never shown, and can the loop learn new ones?

Two questions, two parts:

1. Zero-shot (free, no API calls). 400 attacks carrying organization-specific identifiers (insurance, healthcare,
   finance, legal), with fresh values and fresh carriers. The learned rules (gen-23) were trained on generic PII only,
   so these formats are unseen. Systems: Presidio, learned rules, learned rules + the matching industry pack
   (hand-written seed rules), learned rules + local GLiNER-PII.

2. Learning a new format (spends coach credits). An isolated clone starts from the learned rules and trains on
   healthcare + finance formats only. Afterwards it is scored on held-out values of the trained formats (did it learn
   them?) and on legal + insurance formats it never saw (did anything transfer?).

  python scripts/eval_formats.py                                  # part 1
  PIIGUARD_BUDGET_USD=4 python scripts/eval_formats.py --learn    # parts 1 and 2
"""
from __future__ import annotations

import argparse
import json
import random
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from piiguard.bench import presidio_redactor  # noqa: E402
from piiguard.cli import _classifier  # noqa: E402
from piiguard.eval.datasets import load_jsonl, save_jsonl  # noqa: E402
from piiguard.eval.scoring import is_leak  # noqa: E402
from piiguard.eval.stats import fmt_rate, mcnemar, paired_counts  # noqa: E402
from piiguard.pii.guard import Guard  # noqa: E402
from piiguard.redteam.domains import DOMAINS, domain_guard  # noqa: E402
from piiguard.redteam.encoders import ENCODERS, encode  # noqa: E402
from piiguard.redteam.fresh import FIRST, FRESH_CARRIERS, LAST  # noqa: E402
from piiguard.redteam.generator import CARRIERS, _render  # noqa: E402

D = string.digits
U = string.ascii_uppercase


def _d(rng, k):
    return "".join(rng.choice(D) for _ in range(k))


def _u(rng, k):
    return "".join(rng.choice(U) for _ in range(k))


# type -> (domain, value generator). Shapes match each industry pack's documented format.
FORMATS = {
    "adjuster_badge": ("insurance", lambda r: f"ADJ-{_d(r, 5)}-{_u(r, 2)}"),
    "claim_number": ("insurance", lambda r: f"CLM-{r.randint(2019, 2026)}-{_d(r, 7)}"),
    "policy_number": ("insurance", lambda r: f"POL {_d(r, 2)}-{_d(r, 4)}-{_d(r, 4)}"),
    "mrn": ("healthcare", lambda r: f"MRN {_d(r, 8)}"),
    "npi": ("healthcare", lambda r: f"NPI 1{_d(r, 9)}"),
    "member_id": ("healthcare", lambda r: f"{_u(r, 3)}-{_d(r, 2)}{_u(r, 1)}-{_d(r, 7)}"),
    "account": ("finance", lambda r: f"ACCT {_d(r, 4)}-{_d(r, 4)}-{_d(r, 4)}"),
    "routing": ("finance", lambda r: f"routing {_d(r, 9)}"),
    "iban": ("finance", lambda r: f"{r.choice(['GB', 'DE', 'FR', 'NL'])}{_d(r, 2)} {_u(r, 4)} {_d(r, 4)} {_d(r, 4)} {_d(r, 4)} {_d(r, 2)}"),
    "docket": ("legal", lambda r: f"Case No. {r.randint(1, 9)}:{_d(r, 2)}-{r.choice(['cv', 'cr', 'bk'])}-{_d(r, 5)}"),
    "matter": ("legal", lambda r: f"Matter {r.randint(2019, 2026)}-{_d(r, 4)}-{_u(r, 3)}"),
    "bar_number": ("legal", lambda r: f"Bar No. {_d(r, 6)}"),
}
LABELS = {k: DOMAINS[d]["labels"].get(k, k.replace("_", " ")) for k, (d, _) in FORMATS.items()}
TRAINED = {"healthcare", "finance"}   # part 2 trains on these
UNSEEN = {"legal", "insurance"}        # and never shows these


def generate(n: int, seed: int, domains: set | None = None, carriers: dict | None = None, exclude: set | None = None) -> list[dict]:
    rng = random.Random(seed)
    types = [t for t, (d, _) in FORMATS.items() if domains is None or d in domains]
    carriers = list((carriers or FRESH_CARRIERS).items())
    out, seen = [], set(exclude or ())
    i = 0
    while len(out) < n:
        i += 1
        t = rng.choice(types)
        value = FORMATS[t][1](rng)
        if value in seen:
            continue
        seen.add(value)
        technique = rng.choice(list(ENCODERS))
        surface = encode(technique, value)
        if surface == value:
            technique = "plain"
        cname, template = rng.choice(carriers)
        person = {"name": f"{rng.choice(FIRST)} {rng.choice(LAST)}"}
        out.append({"id": f"fmt-{seed}-{i:04d}", "technique": technique, "pii_type": t, "domain": FORMATS[t][0], "carrier": cname,
                    "text": _render(template, person, t, surface, LABELS), "surface_forms": [surface], "plain_value": value})
    return out


def score(fn, attacks):
    return [is_leak(fn(a["text"]), a["surface_forms"]) for a in attacks]


def zero_shot(attacks):
    gn = Guard.from_dir(ROOT / "guard")
    gl = Guard.from_dir(ROOT / "guard", _classifier(False, "gliner"))
    pres = presidio_redactor()
    systems = {
        "Microsoft Presidio (default recognizers)": lambda a: pres(a["text"]),
        f"piiguard gen-{gn.rules.version} learned rules": lambda a: gn.redact(a["text"]).text,
        f"piiguard gen-{gn.rules.version} rules + matching industry pack": lambda a: domain_guard(gn, a["domain"]).redact(a["text"]).text,
        f"piiguard gen-{gn.rules.version} rules + local GLiNER-PII": lambda a: gl.redact(a["text"]).text,
    }
    out = {}
    for name, fn in systems.items():
        print(f"running {name} ...", file=sys.stderr, flush=True)
        leaks = [is_leak(fn(a), a["surface_forms"]) for a in attacks]
        by_domain = {}
        for a, l in zip(attacks, leaks):
            by_domain.setdefault(a["domain"], [0, 0])
            by_domain[a["domain"]][0] += l
            by_domain[a["domain"]][1] += 1
        out[name] = {"leaks": sum(leaks), "n": len(leaks), "by_domain": by_domain}
    return out


def learn(attacks, generations: int):
    from ablate_gates import _sh, make_arm, run_arm
    train_all = generate(100, seed=9101, domains=TRAINED, carriers=CARRIERS, exclude={a["plain_value"] for a in attacks})
    train, val = train_all[:75], train_all[75:]
    base = ROOT.parent / "ablation-formats"
    base.mkdir(exist_ok=True)
    path = make_arm(base, "learn_new_formats", train, val, start_ref="HEAD")
    run_arm(path, dict(gate="threshold", memory=True, clean="small"), generations, lambda s: print(s, file=sys.stderr))
    before = Guard.from_dir(ROOT / "guard")
    after = Guard.from_dir(path / "guard")
    res = {}
    for group, doms in (("trained formats (healthcare, finance)", TRAINED), ("unseen formats (legal, insurance)", UNSEEN)):
        sub = [a for a in attacks if a["domain"] in doms]
        b = [is_leak(before.redact(a["text"]).text, a["surface_forms"]) for a in sub]
        f = [is_leak(after.redact(a["text"]).text, a["surface_forms"]) for a in sub]
        fixed, broken = paired_counts(b, f)
        res[group] = {"n": len(sub), "before": sum(b), "after": sum(f), "fixed": fixed, "broken": broken, "p": mcnemar(fixed, broken)}
    hist = path / "runs" / "history.jsonl"
    recs = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()] if hist.exists() else []
    spend = [l for l in (path / "runs" / "ablation.log").read_text().splitlines() if l.startswith("[spend]")]
    return {"train": len(train), "val": len(val), "generations": len(recs), "accepted": sum(r["accepted"] for r in recs),
            "rules_before": len(before.rules.rules), "rules_after": len(after.rules.rules), "groups": res,
            "spend": spend[-1][8:] if spend else "n/a"}


def render(report: dict) -> str:
    z = report["zero_shot"]
    doms = ["insurance", "healthcare", "finance", "legal"]
    lines = [f"| system | all unseen formats (n={report['n']}) | " + " | ".join(doms) + " |", "|---|---|" + "---|" * len(doms)]
    for name, s in z.items():
        cells = [f"{s['by_domain'][d][0]}/{s['by_domain'][d][1]}" for d in doms]
        lines.append(f"| {name} | {fmt_rate(s['leaks'], s['n'])} | " + " | ".join(cells) + " |")
    if report.get("learn"):
        L = report["learn"]
        lines.append(f"\nLearning a new format: {L['train']} training attacks on healthcare and finance formats only, "
                     f"{L['generations']} generations, {L['accepted']} accepted, rules {L['rules_before']} to {L['rules_after']}.\n")
        lines.append("| held-out group | leak before | leak after | fixed | broke | p |")
        lines.append("|---|---|---|---|---|---|")
        for g, r in L["groups"].items():
            p = "<0.001" if r["p"] < 0.001 else f"{r['p']:.3f}"
            lines.append(f"| {g} | {fmt_rate(r['before'], r['n'])} | {fmt_rate(r['after'], r['n'])} | {r['fixed']} | {r['broken']} | {p} |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--learn", action="store_true")
    ap.add_argument("--generations", type=int, default=6)
    a = ap.parse_args()
    path = ROOT / "data" / "attacks-formats" / "heldout.jsonl"
    if not path.exists():
        save_jsonl(path, generate(400, seed=8080))
    attacks = load_jsonl(path)
    report = {"n": len(attacks), "zero_shot": zero_shot(attacks)}
    if a.learn:
        report["learn"] = learn(attacks, a.generations)
    out = ROOT / "runs" / "formats.json"
    if out.exists() and not a.learn:
        prev = json.loads(out.read_text())
        if prev.get("learn"):
            report["learn"] = prev["learn"]
    out.write_text(json.dumps(report, indent=2))
    print(render(report))


if __name__ == "__main__":
    main()
