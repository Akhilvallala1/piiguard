"""Score human-written attacks from data/attacks-human/*.csv (template.csv is skipped). No API calls.

A row counts if `hidden_as` appears verbatim in `text` and is not simply the plain value. A leak means `hidden_as`
survives redaction. Invalid rows are reported, never silently dropped.

  python scripts/eval_human.py
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiguard.cli import _classifier  # noqa: E402
from piiguard.coach.gate import GuardRepo  # noqa: E402
from piiguard.eval.scoring import is_leak  # noqa: E402
from piiguard.eval.stats import fmt_rate  # noqa: E402
from piiguard.pii.guard import Guard  # noqa: E402

TYPES = {"ssn", "card", "phone", "email", "dob"}


def load(folder: Path) -> tuple[list[dict], list[str]]:
    rows, problems = [], []
    for f in sorted(folder.glob("*.csv")):
        if f.name == "template.csv":
            continue
        with f.open(newline="", encoding="utf-8") as fh:
            for i, r in enumerate(csv.DictReader(fh), start=2):
                where = f"{f.name}:{i}"
                text, hidden, value = (r.get("text") or ""), (r.get("hidden_as") or ""), (r.get("value") or "").strip()
                if not text or not hidden or not value:
                    problems.append(f"{where}: missing text, hidden_as or value")
                elif hidden not in text:
                    problems.append(f"{where}: hidden_as does not appear in text")
                elif hidden.strip() == value:
                    problems.append(f"{where}: hidden_as is the plain value, not an evasion")
                elif (r.get("type") or "").strip().lower() not in TYPES:
                    problems.append(f"{where}: type must be one of {sorted(TYPES)}")
                else:
                    rows.append({"id": where, "text": text, "surface_forms": [hidden], "plain_value": value,
                                 "pii_type": r["type"].strip().lower(), "technique": (r.get("trick") or "").strip() or "unlabeled",
                                 "author": (r.get("author") or "").strip() or "anonymous"})
    return rows, problems


def main():
    rows, problems = load(ROOT / "data" / "attacks-human")
    for p in problems:
        print(f"skipped {p}", file=sys.stderr)
    if not rows:
        print("no valid human-written attacks yet; add <name>.csv files to data/attacks-human/", file=sys.stderr)
        return
    from piiguard.bench import presidio_redactor
    g0 = Guard.from_texts(*GuardRepo(ROOT).files_at("gen-0"))
    gn = Guard.from_dir(ROOT / "guard")
    gl = Guard.from_dir(ROOT / "guard", _classifier(False, "gliner"))
    pres = presidio_redactor()
    systems = {
        "Microsoft Presidio (default recognizers)": pres,
        "piiguard gen-0 rules": lambda t: g0.redact(t).text,
        f"piiguard gen-{gn.rules.version} learned rules": lambda t: gn.redact(t).text,
        f"piiguard gen-{gn.rules.version} rules + local GLiNER-PII": lambda t: gl.redact(t).text,
    }
    out = {"n": len(rows), "skipped": problems, "authors": sorted({r["author"] for r in rows}), "systems": {}}
    lines = [f"| system | leak on human-written attacks (n={len(rows)}) |", "|---|---|"]
    for name, fn in systems.items():
        leaks = [is_leak(fn(r["text"]), r["surface_forms"]) for r in rows]
        out["systems"][name] = {"leaks": sum(leaks), "missed": [r["id"] for r, l in zip(rows, leaks) if l]}
        lines.append(f"| {name} | {fmt_rate(sum(leaks), len(rows))} |")
    (ROOT / "runs" / "human.json").write_text(json.dumps(out, indent=2))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
