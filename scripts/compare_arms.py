"""Compare the memory-off and memory-on arms: same starting rules, same Nemotron-PII training slice, four generations each.
Scores each arm's final rules on the Nemotron-PII held-out slice the coach never saw (rules only, then rules + routed classifier)."""
from __future__ import annotations

import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from piiguard.env import load_dotenv
from piiguard.eval.datasets import load_jsonl
from piiguard.eval.harness import CLEAN_SAMPLES, evaluate_attacks, evaluate_clean
from piiguard.pii.guard import Guard
from piiguard.memory import ShapeLedger

load_dotenv()
ARMS = {"memory off": ROOT.parent / "ablation" / "nomem", "memory on": ROOT.parent / "ablation" / "mem"}
heldout = load_jsonl(ROOT / "data/attacks-nemotron/heldout.jsonl")
use_clf = "--llm" in sys.argv
clf = None
if use_clf:
    from piiguard.cli import _classifier
    clf = _classifier(True)

def score(guard):
    _, a = evaluate_attacks(guard, heldout); _, c = evaluate_clean(guard, CLEAN_SAMPLES)
    return a["leak_rate"], c["fp_rate"]

import subprocess as _sp
rows = []
start = Guard.from_texts(_sp.run(["git", "show", "gen-14:guard/rules.yaml"], cwd=ARMS["memory off"], capture_output=True, text=True).stdout)  # both arms start here
for name, path in ARMS.items():
    hist = [json.loads(l) for l in (path / "runs/history.jsonl").read_text().splitlines() if l.strip()] if (path / "runs/history.jsonl").exists() else []
    g = Guard.from_dir(path / "guard", clf)
    leak, fp = score(g)
    accepted = sum(1 for r in hist if r["accepted"])
    flagged = sum(1 for r in hist if r.get("regressions"))
    # silent regressions: did an ACCEPTED generation drop a shape the previous rules caught? (replay with a ledger)
    silent = 0
    try:
        import subprocess, tempfile
        tags = sorted(int(t.split("-")[1]) for t in subprocess.run(["git", "tag", "--list", "gen-*"], cwd=path, capture_output=True, text=True).stdout.split() if int(t.split("-")[1]) >= 100)
        train = load_jsonl(path / "data/attacks-nemotron/train.jsonl") + load_jsonl(path / "data/attacks-nemotron/val.jsonl")
        prev = None
        for t in tags:
            cur = Guard.from_texts(subprocess.run(["git", "show", f"gen-{t}:guard/rules.yaml"], cwd=path, capture_output=True, text=True).stdout)
            if prev is not None:
                with tempfile.TemporaryDirectory() as td:
                    led = ShapeLedger(Path(td) / "s.jsonl"); led.record(prev, train, gen=t - 1)
                    if led.regressions(cur): silent += 1
            prev = cur
    except Exception as e:  # noqa: BLE001
        silent = f"n/a ({type(e).__name__})"
    rows.append({"arm": name, "generations": len(hist), "accepted": accepted, "regressions_flagged": flagged, "silent_regressions_in_accepted": silent,
                 "heldout_leak": leak, "fp": fp, "rules": len(g.rules.rules)})
sl, sf = score(Guard(start.rules, Guard.from_dir(ROOT / "guard").prompt, clf))
print(f"starting rules (gen-14): held-out leak {sl:.1%} fp {sf:.1%}  [{'rules + routed classifier' if use_clf else 'rules only'}]")
print(f"{'arm':<11} {'gens':>4} {'accepted':>8} {'flagged':>8} {'silent':>7} {'rules':>5} {'held-out leak':>14} {'fp':>6}")
for r in rows:
    print(f"{r['arm']:<11} {r['generations']:>4} {r['accepted']:>8} {r['regressions_flagged']:>8} {r['silent_regressions_in_accepted']!s:>7} {r['rules']:>5} {r['heldout_leak']:>14.1%} {r['fp']:>6.1%}")
(ROOT / "runs" / f"ablation-memory{'-llm' if use_clf else ''}.json").write_text(json.dumps({"start": {"leak": sl, "fp": sf}, "arms": rows}, indent=2))
