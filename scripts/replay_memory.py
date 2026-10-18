"""Replay today's coach proposals against a shape ledger built from the guard that preceded each one.
Question: how many proposals silently dropped a shape the previous rules already caught, i.e. regressions the
30-sample validation set did not see? This is what the shape-memory gate would have caught."""
from __future__ import annotations

import json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from piiguard.eval.datasets import load_jsonl
from piiguard.memory import ShapeLedger
from piiguard.pii.guard import Guard
from piiguard.coach.gate import GuardRepo

repo = GuardRepo(ROOT)
hist = [json.loads(l) for l in (ROOT / "runs/history.jsonl").read_text().splitlines() if l.strip()]
tags = sorted(int(t.split("-")[1]) for t in subprocess.run(["git", "tag", "--list", "gen-*"], cwd=ROOT, capture_output=True, text=True).stdout.split())
general = load_jsonl(ROOT / "data/attacks/train.jsonl") + load_jsonl(ROOT / "data/attacks/val.jsonl")
insurance = load_jsonl(ROOT / "data/attacks-insurance/train.jsonl") + load_jsonl(ROOT / "data/attacks-insurance/val.jsonl")

rows = []
for r in hist:
    if not r.get("proposal") or not r["proposal"].get("rules_yaml"):
        continue
    gen = r["gen"]
    prev_tag = max([t for t in tags if t < gen] or [0])
    before = Guard.from_texts(*repo.files_at(f"gen-{prev_tag}"))
    attacks = insurance if gen >= 17 else general
    with tempfile.TemporaryDirectory() as td:
        led = ShapeLedger(Path(td) / "s.jsonl")
        remembered = led.record(before, attacks, gen=prev_tag)
        try:
            cand = Guard.from_texts(r["proposal"]["rules_yaml"])
        except Exception as e:  # noqa: BLE001
            rows.append((gen, r["accepted"], remembered, "invalid", str(e)[:50])); continue
        lost = led.regressions(cand)
    rows.append((gen, r["accepted"], remembered, len(lost), ", ".join(sorted({e["surface"] for e in lost}))[:70]))

print(f"{'gen':>3} {'kept':<5} {'remembered':>10} {'regressed':>9}  examples")
silent = 0; accepted_with_regress = 0
for gen, acc, rem, lost, ex in rows:
    print(f"{gen:>3} {'yes' if acc else 'no':<5} {rem:>10} {lost!s:>9}  {ex}")
    if isinstance(lost, int) and lost > 0:
        silent += 1
        if acc:
            accepted_with_regress += 1
print(f"\n{len(rows)} proposals replayed; {silent} regressed at least one remembered shape; {accepted_with_regress} of those were ACCEPTED by the old gate (silent regressions).")
