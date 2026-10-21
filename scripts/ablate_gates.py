"""Ablation: which gate trains a better guard, on equal coach budget?

Four arms, each an isolated clone of this repo reset to the same starting rules (gen-0), each running the same number
of coach generations on the same training data (fresh values, so no memorization path), then scored on two held-out
sets the coach never saw: data/attacks-fresh (deterministic encoders) and data/attacks-crossfamily (other model
families, including their own techniques). The main repo's guard/ and tags are never touched.

  arm                   gate        memory   clean corpus for the gate
  threshold             5 points    off      25 samples   (the original loop)
  threshold+memory      5 points    on       25 samples
  stat                  McNemar     off      1,075 samples
  stat+memory           McNemar     on       1,075 samples

  PIIGUARD_BUDGET_USD=20 python scripts/ablate_gates.py --generations 6
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from piiguard.eval.clean_corpus import generate_clean  # noqa: E402
from piiguard.eval.datasets import load_jsonl, save_jsonl  # noqa: E402
from piiguard.eval.harness import CLEAN_SAMPLES  # noqa: E402
from piiguard.eval.scoring import is_leak  # noqa: E402
from piiguard.eval.stats import fmt_rate, mcnemar, paired_counts  # noqa: E402
from piiguard.pii.guard import Guard  # noqa: E402
from piiguard.redteam.fresh import generate_fresh  # noqa: E402
from piiguard.redteam.generator import SEED_PEOPLE  # noqa: E402

ARMS = {
    "threshold": dict(gate="threshold", memory=False, clean="small"),
    "threshold+memory": dict(gate="threshold", memory=True, clean="small"),
    "stat": dict(gate="stat", memory=False, clean="large"),
    "stat+memory": dict(gate="stat", memory=True, clean="large"),
}

# Coach comparison: same gate (stat+memory), same data, same generations; only the coach model changes.
COACH_ARMS = {
    "coach: Nemotron 3 Super": dict(gate="stat", memory=True, clean="large", coach="nvidia/NVIDIA-Nemotron-3-Super-120B-A12B"),
    "coach: gpt-oss-120b": dict(gate="stat", memory=True, clean="large", coach="openai/gpt-oss-120b"),
    "coach: DeepSeek V4 Pro": dict(gate="stat", memory=True, clean="large", coach="deepseek-ai/DeepSeek-V4-Pro"),
}


def _sh(*args, cwd):
    return subprocess.run(list(args), cwd=cwd, check=True, capture_output=True, text=True).stdout


def training_set(seed: int = 777) -> tuple[list[dict], list[dict]]:
    """Fresh-value train/val, disjoint from every held-out value, wrapped in the ORIGINAL carrier templates so that
    neither held-out set shares carriers with training (fresh uses FRESH_CARRIERS, cross-family uses model text)."""
    from piiguard.redteam.generator import CARRIERS
    seen = {v for p in SEED_PEOPLE for v in p.values()}
    for d in ("attacks-fresh", "attacks-crossfamily"):
        p = ROOT / "data" / d / "heldout.jsonl"
        if p.exists():
            seen |= {a["plain_value"] for a in load_jsonl(p)}
    rows = generate_fresh(240, seed=seed, exclude_values=seen, carriers=CARRIERS)
    return rows[:180], rows[180:]


def make_arm(base: Path, slug: str, train, val) -> Path:
    path = base / slug
    if path.exists():
        shutil.rmtree(path)
    _sh("git", "clone", "-q", "--no-hardlinks", str(ROOT), str(path), cwd=base)
    _sh("git", "checkout", "-q", "-B", "ablation", cwd=path)
    _sh("git", "checkout", "gen-0", "--", "guard/", cwd=path)
    _sh("git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "ablation: reset guard to gen-0", "--allow-empty", cwd=path)
    for t in _sh("git", "tag", "--list", "gen-*", cwd=path).split():
        _sh("git", "tag", "-d", t, cwd=path)
    _sh("git", "tag", "gen-0", cwd=path)
    _sh("git", "config", "commit.gpgsign", "false", cwd=path)
    if (ROOT / ".env").exists():  # gitignored, so the clone lacks it; stays local, never committed
        shutil.copy2(ROOT / ".env", path / ".env")
    data = path / "data" / "ablation-train"
    save_jsonl(data / "train.jsonl", train)
    save_jsonl(data / "val.jsonl", val)
    save_jsonl(data / "heldout.jsonl", val[:10])  # the CLI needs a heldout file; scoring uses the real held-out sets below
    (path / "runs").mkdir(exist_ok=True)
    for f in ("history.jsonl", "shapes.jsonl"):
        (path / "runs" / f).unlink(missing_ok=True)
    return path


def run_arm(path: Path, cfg: dict, generations: int, log):
    cmd = [sys.executable, "-m", "piiguard.cli", "improve", "--generations", str(generations), "--data", "data/ablation-train",
           "--gate", cfg["gate"], "--clean", cfg["clean"], "--max-new-fp", str(cfg.get("max_new_fp", 0))]
    if not cfg["memory"]:
        cmd.append("--no-memory")
    if cfg.get("coach"):
        cmd += ["--coach-model", cfg["coach"]]
    env = {**os.environ, "PYTHONPATH": str(path)}
    p = subprocess.run(cmd, cwd=path, env=env, capture_output=True, text=True)
    (path / "runs" / "ablation.log").write_text(p.stdout + p.stderr)
    log(f"[{path.name}] exit {p.returncode}: " + (p.stderr.strip().splitlines() or ["(no output)"])[-1][:200])
    return p.returncode


def score(path: Path, sets: dict, clean: list[str]) -> dict:
    g = Guard.from_dir(path / "guard")
    out = {"rules": len(g.rules.rules)}
    for name, attacks in sets.items():
        out[name] = [is_leak(g.redact(a["text"]).text, a["surface_forms"]) for a in attacks]
    out["fp"] = [g.redact(t).text != t for t in clean]
    hist = path / "runs" / "history.jsonl"
    recs = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()] if hist.exists() else []
    out["generations"] = len(recs)
    out["accepted"] = sum(1 for r in recs if r.get("accepted"))
    return out


def _slug(name: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--generations", type=int, default=6)
    ap.add_argument("--workdir", default=str(ROOT.parent / "ablation-gates"))
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--compare", default="gates", choices=["gates", "coaches"])
    ap.add_argument("--max-new-fp", type=int, default=None, help="override the stat gate's new-false-positive tolerance for every arm")
    a = ap.parse_args()
    arms = {k: dict(v) for k, v in (ARMS if a.compare == "gates" else COACH_ARMS).items()}
    if a.max_new_fp is not None:
        for v in arms.values():
            v["max_new_fp"] = a.max_new_fp
    base = Path(a.workdir)
    base.mkdir(parents=True, exist_ok=True)
    log = lambda s: print(s, file=sys.stderr, flush=True)
    train, val = training_set()
    paths = {name: base / _slug(name) for name in arms}
    if not a.score_only:
        for name in arms:
            make_arm(base, _slug(name), train, val)
        log(f"arms ready in {base}; running {a.generations} generations each")
        with ThreadPoolExecutor(len(arms)) as ex:
            list(ex.map(lambda kv: run_arm(paths[kv[0]], kv[1], a.generations, log), arms.items()))

    sets = {"fresh": load_jsonl(ROOT / "data/attacks-fresh/heldout.jsonl"),
            "crossfamily": load_jsonl(ROOT / "data/attacks-crossfamily/heldout.jsonl")}
    clean = list(CLEAN_SAMPLES) + generate_clean()
    start_dir = base / "_start"
    if not start_dir.exists():
        (start_dir / "guard").mkdir(parents=True)
        for f in ("rules.yaml", "prompt.md"):
            (start_dir / "guard" / f).write_text(_sh("git", "show", f"gen-0:guard/{f}", cwd=ROOT))
    results = {"start (gen-0)": score(start_dir, sets, clean)}
    for name in arms:
        results[name] = score(paths[name], sets, clean)
    ref = results[next(iter(arms))]
    report = {"generations": a.generations, "train": len(train), "val": len(val), "arms": {}}
    for name, r in results.items():
        row = {"rules": r["rules"], "generations": r.get("generations", 0), "accepted": r.get("accepted", 0),
               "fp": sum(r["fp"]), "n_clean": len(clean)}
        for s in sets:
            fixed, broken = paired_counts(ref[s], r[s])
            row[s] = {"leaks": sum(r[s]), "n": len(r[s]), "vs_threshold_fixed": fixed, "vs_threshold_broken": broken,
                      "p_better_than_threshold": mcnemar(fixed, broken), "p_worse_than_threshold": mcnemar(broken, fixed)}
        report["arms"][name] = row
    report["compare"] = a.compare
    report["max_new_fp"] = a.max_new_fp
    report["spend"] = {name: _arm_spend(paths[name]) for name in arms}
    tag = Path(a.workdir).name.removeprefix("ablation-")
    (ROOT / "runs" / f"ablation-{tag}.json").write_text(json.dumps(report, indent=2))
    print(render(report))


def _arm_spend(path: Path) -> str:
    log = path / "runs" / "ablation.log"
    if not log.exists():
        return "n/a"
    lines = [l for l in log.read_text().splitlines() if l.startswith("[spend]")]
    return lines[-1][len("[spend] "):] if lines else "n/a"


def render(report: dict) -> str:
    lines = ["| arm | accepted / generations | rules | fresh leak (n=500) | cross-family leak (n=500) | false positives (n=1075) |",
             "|---|---|---|---|---|---|"]
    for name, r in report["arms"].items():
        f, x = r["fresh"], r["crossfamily"]
        lines.append(f"| {name} | {r['accepted']} / {r['generations']} | {r['rules']} | {fmt_rate(f['leaks'], f['n'])} | "
                     f"{fmt_rate(x['leaks'], x['n'])} | {fmt_rate(r['fp'], r['n_clean'])} |")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
