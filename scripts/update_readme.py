"""Inject the live results (generation history, held-out before/after, benchmark) into README.md between markers."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PY = sys.executable


def section(name: str, body: str, text: str) -> str:
    start, end = f"<!-- {name}:start -->", f"<!-- {name}:end -->"
    block = f"{start}\n{body.strip()}\n{end}"
    if start in text and end in text:
        return re.sub(re.escape(start) + r".*?" + re.escape(end), lambda _: block, text, flags=re.S)
    raise SystemExit(f"README is missing markers for {name}")


def main():
    text = README.read_text()
    history = subprocess.run([PY, "-m", "piiguard.cli", "report", "--markdown"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    text = section("generations", history, text)
    bench_path = ROOT / "runs" / "bench.json"
    if bench_path.exists():
        from piiguard.bench import render_table
        rows = json.loads(bench_path.read_text())["rows"]
        text = section("bench", render_table(rows), text)
    ins = ROOT / "runs" / "report-insurance.json"
    if ins.exists():
        d = json.loads(ins.read_text())
        hb, ha = d["heldout_before"], d["heldout_after"]
        body = (f"| set | gen-0 rules | current rules |\n|---|---|---|\n"
                f"| insurance held-out leak rate (n={hb.get('n','?')}) | {hb['leak_rate']:.1%} | {ha['leak_rate']:.1%} |\n"
                f"| false positives on clean traffic | {d['fp_before']['fp_rate']:.1%} | {d['fp_after']['fp_rate']:.1%} |")
        text = section("insurance", body, text)
    README.write_text(text)
    print("README updated")


if __name__ == "__main__":
    main()
