"""piiguard CLI: gen-attacks | eval | improve | report | serve | redact | models"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "attacks"


def _classifier(use_llm: bool):
    if not use_llm:
        return None
    from .pii.classifier import LLMClassifier
    return LLMClassifier()


def _load_sets(data: Path):
    from .eval.datasets import load_jsonl
    return {name: load_jsonl(data / f"{name}.jsonl") for name in ("train", "val", "heldout")}


def cmd_models(_):
    from .crusoe import list_models
    print("\n".join(list_models()))


def cmd_redact(a):
    from .pii.guard import Guard
    g = Guard.from_dir(ROOT / "guard", _classifier(a.llm))
    red = g.redact(a.text)
    print(red.text)
    if a.verbose:
        print(json.dumps(red.mapping, indent=2), file=sys.stderr)


def cmd_gen(a):
    from .eval.datasets import save_jsonl
    from .redteam.generator import generate_attacks, split_dataset
    carrier_fn = None
    if a.llm_carriers:
        from .redteam.carriers import llm_carrier
        carrier_fn = llm_carrier
    attacks = generate_attacks(a.n, seed=a.seed, carrier_fn=carrier_fn)
    train, val, heldout = split_dataset(attacks, seed=a.seed)
    out = Path(a.out)
    for name, rows in (("train", train), ("val", val), ("heldout", heldout)):
        save_jsonl(out / f"{name}.jsonl", rows)
    print(f"wrote {len(train)} train / {len(val)} val / {len(heldout)} heldout attacks to {out}", file=sys.stderr)


def cmd_eval(a):
    from .eval.harness import CLEAN_SAMPLES, evaluate_attacks, evaluate_clean
    from .pii.guard import Guard
    sets = _load_sets(Path(a.data))
    g = Guard.from_dir(ROOT / "guard", _classifier(a.llm))
    results, scores = evaluate_attacks(g, sets[a.set])
    _, clean = evaluate_clean(g, CLEAN_SAMPLES)
    report = {"set": a.set, "llm": a.llm, "rules_version": g.rules.version, "attacks": scores, "clean": clean}
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{a.set}: leak rate {scores['leak_rate']:.2%} ({scores['leaks']}/{scores['n']}), false positives {clean['fp_rate']:.2%}")
        for t, v in scores["by_technique"].items():
            print(f"  {t:<20} {v:.0%}")
        if a.show_misses:
            for r in results:
                if r["leaked"]:
                    print(f"  MISS {r['id']} [{r['technique']}/{r['pii_type']}] -> {r['redacted_text'][:100]!r}")


def cmd_improve(a):
    from .coach.retrospective import propose
    from .eval.harness import CLEAN_SAMPLES, evaluate_attacks, evaluate_clean
    from .loop import run_generation
    from .pii.guard import Guard
    sets = _load_sets(Path(a.data))
    clf = _classifier(a.llm)
    log = lambda s: print(s, file=sys.stderr, flush=True)

    g0 = Guard.from_dir(ROOT / "guard", clf)
    _, h0 = evaluate_attacks(g0, sets["heldout"])
    _, c0 = evaluate_clean(g0, CLEAN_SAMPLES)
    log(f"[gen 0] HELD-OUT leak rate {h0['leak_rate']:.2%} | fp {c0['fp_rate']:.2%} | rules v{g0.rules.version}")

    coach = (lambda misses, r, p, s: propose(misses, r, p, s))
    start = a.start_gen
    records = []
    for gen in range(start, start + a.generations):
        rec = run_generation(ROOT, gen, sets["train"], sets["val"], CLEAN_SAMPLES, coach, classifier=clf,
                             min_leak_delta=a.min_delta, max_fp_increase=a.max_fp, log=log)
        records.append(rec)
        if rec["train_before"]["leak_rate"] == 0.0:
            log("no misses left on train; stopping early")
            break

    gN = Guard.from_dir(ROOT / "guard", clf)
    _, hN = evaluate_attacks(gN, sets["heldout"])
    _, cN = evaluate_clean(gN, CLEAN_SAMPLES)
    log(f"[final] HELD-OUT leak rate {h0['leak_rate']:.2%} -> {hN['leak_rate']:.2%} | fp {c0['fp_rate']:.2%} -> {cN['fp_rate']:.2%} | rules v{gN.rules.version}")
    report = {"heldout_before": h0, "heldout_after": hN, "fp_before": c0, "fp_after": cN,
              "generations": [{k: v for k, v in r.items() if k != "proposal"} for r in records], "llm": a.llm}
    (ROOT / "runs").mkdir(exist_ok=True)
    (ROOT / "runs" / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"heldout_before": h0["leak_rate"], "heldout_after": hN["leak_rate"], "fp_before": c0["fp_rate"], "fp_after": cN["fp_rate"]}))


def cmd_report(_):
    hist = ROOT / "runs" / "history.jsonl"
    if not hist.exists():
        print("no runs yet"); return
    print(f"{'gen':>3} {'ok':<3} {'val leak before->after':<26} {'fp before->after':<20} rationale")
    for line in hist.read_text().splitlines():
        r = json.loads(line)
        print(f"{r['gen']:>3} {'Y' if r['accepted'] else 'n':<3} {r['val_before']['leak_rate']:.2f} -> {r['val_after']['leak_rate']:.2f}{'':<14} {r['fp_before']['fp_rate']:.2f} -> {r['fp_after']['fp_rate']:.2f}{'':<8} {r['rationale'][:70]}")
    rep = ROOT / "runs" / "report.json"
    if rep.exists():
        d = json.loads(rep.read_text())
        print(f"\nHELD-OUT leak rate: {d['heldout_before']['leak_rate']:.2%} -> {d['heldout_after']['leak_rate']:.2%}   false positives: {d['fp_before']['fp_rate']:.2%} -> {d['fp_after']['fp_rate']:.2%}")


def cmd_serve(a):
    import uvicorn
    from .proxy import create_app, resolve_serve_config
    cfg = resolve_serve_config(a.host, os.environ.get("GUARD_PROXY_TOKEN"))
    if cfg.generated:
        print(f"GUARD_PROXY_TOKEN not set; using one-off token: {cfg.token}", file=sys.stderr)
    app = create_app(token=cfg.token, classifier=_classifier(a.llm))
    print(f"piiguard proxy on http://{cfg.host}:{a.port}  (llm classifier: {'on' if a.llm else 'off'})", file=sys.stderr)
    uvicorn.run(app, host=cfg.host, port=a.port, log_level="warning")


def main(argv=None):
    from .env import load_dotenv
    load_dotenv()
    p = argparse.ArgumentParser(prog="piiguard")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("models", help="list Crusoe model ids").set_defaults(fn=cmd_models)

    s = sub.add_parser("redact", help="redact a string with the current guard"); s.add_argument("text"); s.add_argument("--llm", action="store_true"); s.add_argument("-v", "--verbose", action="store_true"); s.set_defaults(fn=cmd_redact)

    s = sub.add_parser("gen-attacks", help="generate red-team attack sets"); s.add_argument("--n", type=int, default=150); s.add_argument("--seed", type=int, default=42); s.add_argument("--out", default=str(DATA)); s.add_argument("--llm-carriers", action="store_true"); s.set_defaults(fn=cmd_gen)

    s = sub.add_parser("eval", help="evaluate current guard"); s.add_argument("--data", default=str(DATA)); s.add_argument("--set", default="heldout", choices=["train", "val", "heldout"]); s.add_argument("--llm", action="store_true"); s.add_argument("--json", action="store_true"); s.add_argument("--show-misses", action="store_true"); s.set_defaults(fn=cmd_eval)

    s = sub.add_parser("improve", help="run N self-improvement generations"); s.add_argument("--generations", type=int, default=5); s.add_argument("--start-gen", type=int, default=1); s.add_argument("--data", default=str(DATA)); s.add_argument("--llm", action="store_true"); s.add_argument("--min-delta", type=float, default=0.05); s.add_argument("--max-fp", type=float, default=0.05); s.set_defaults(fn=cmd_improve)

    sub.add_parser("report", help="print generation history and held-out before/after").set_defaults(fn=cmd_report)

    s = sub.add_parser("serve", help="run the guard proxy"); s.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 (with GUARD_PROXY_TOKEN set) so a NemoClaw sandbox can reach it"); s.add_argument("--port", type=int, default=8787); s.add_argument("--llm", action="store_true"); s.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
