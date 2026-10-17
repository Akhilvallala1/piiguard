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

    if a.start_gen > 1:  # resuming: the true baseline is the gen-0 tag, not whatever is in the working tree now
        from .coach.gate import GuardRepo
        g0 = Guard.from_texts(*GuardRepo(ROOT).files_at(a.baseline_tag), classifier=clf)
        log(f"[resume] baseline from tag {a.baseline_tag}; continuing at gen {a.start_gen}")
    else:
        g0 = Guard.from_dir(ROOT / "guard", clf)
    _, h0 = evaluate_attacks(g0, sets["heldout"])
    _, c0 = evaluate_clean(g0, CLEAN_SAMPLES)
    log(f"[gen 0] HELD-OUT leak rate {h0['leak_rate']:.2%} | fp {c0['fp_rate']:.2%} | rules v{g0.rules.version}")

    hist_path = ROOT / "runs" / "history.jsonl"

    def coach(misses, r, p, s):
        history = [json.loads(l) for l in hist_path.read_text().splitlines() if l.strip()] if hist_path.exists() else []
        return propose(misses, r, p, s, classifier_enabled=a.llm, history=history)
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


def cmd_bench(a):
    from .bench import presidio_redactor, render_table, run_bench
    from .coach.gate import GuardRepo
    from .eval.harness import CLEAN_SAMPLES
    from .pii.guard import Guard
    sets = _load_sets(Path(a.data))
    attacks = sets[a.set]
    systems = {"NemoClaw sandbox policy only (no content layer)": lambda t: t}
    if not a.no_presidio:
        print("loading Presidio + spaCy en_core_web_lg ...", file=sys.stderr)
        systems["Microsoft Presidio (default recognizers)"] = presidio_redactor()
        systems["Microsoft Presidio (scoped: SSN, email, phone, card)"] = presidio_redactor(entities=["US_SSN", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"])
    g0 = Guard.from_texts(*GuardRepo(ROOT).files_at(a.baseline_tag))
    systems[f"piiguard {a.baseline_tag} (hand-written rules)"] = lambda t, g=g0: g.redact(t).text
    gn = Guard.from_dir(ROOT / "guard")
    systems[f"piiguard gen-{gn.rules.version} rules (self-improved, no model call)"] = lambda t, g=gn: g.redact(t).text
    if a.llm:
        gl = Guard.from_dir(ROOT / "guard", _classifier(True))
        systems[f"piiguard gen-{gn.rules.version} rules + Nemotron 3.5 Lightning classifier"] = lambda t, g=gl: g.redact(t).text
    rows = run_bench(systems, attacks, CLEAN_SAMPLES)
    (ROOT / "runs").mkdir(exist_ok=True)
    (ROOT / "runs" / "bench.json").write_text(json.dumps({"set": a.set, "rows": rows}, indent=2))
    print(render_table(rows))
    if a.by_technique:
        techs = sorted({t for r in rows for t in r["by_technique"]})
        print("\n| technique | " + " | ".join(r["system"].split(" (")[0] for r in rows) + " |")
        print("|---|" + "---|" * len(rows))
        for t in techs:
            print(f"| {t} | " + " | ".join(f"{r['by_technique'].get(t, 0):.0%}" for r in rows) + " |")


def cmd_prune(a):
    """Unlearning step: remove rules whose removal changes nothing on val + clean; commit as its own generation."""
    from .coach.gate import GuardRepo
    from .eval.harness import CLEAN_SAMPLES, evaluate_attacks
    from .pii.guard import Guard
    from .prune import prune_rules
    sets = _load_sets(Path(a.data))
    repo = GuardRepo(ROOT)
    rules_yaml, prompt_md = repo.current_files()
    # Ablate against everything the coach is allowed to see (train + val); held-out stays blind and is only a tripwire.
    res = prune_rules(rules_yaml, sets["train"] + sets["val"], CLEAN_SAMPLES, protect=("ssn", "email", "phone_us", "credit_card"))
    for n in res.notes:
        print("  " + n, file=sys.stderr)
    before_h = evaluate_attacks(Guard.from_texts(rules_yaml), sets["heldout"])[1]["leak_rate"]
    after_h = evaluate_attacks(Guard.from_texts(res.rules_yaml), sets["heldout"])[1]["leak_rate"]
    print(f"rules {len(res.kept) + len(res.dropped)} -> {len(res.kept)} | train+val leak {res.leak_before:.2%} -> {res.leak_after:.2%} | fp {res.fp_before:.2%} -> {res.fp_after:.2%} | held-out tripwire {before_h:.2%} -> {after_h:.2%}")
    if not res.dropped:
        print("nothing to prune"); return
    if after_h > before_h:
        print("held-out leak would rise; not committing (val/clean were blind to this)"); return
    if a.dry_run:
        print("dry run: dropped would be " + ", ".join(res.dropped)); return
    import re as _re
    stamped = _re.sub(r"^'?version'?:.*$", f"version: {a.gen}", res.rules_yaml, count=1, flags=_re.M)
    repo.stage(stamped, prompt_md)
    sha = repo.commit(f"gen-{a.gen}", f"gen {a.gen}: prune {len(res.dropped)} rule(s) whose removal changed nothing: {', '.join(res.dropped)}")
    rec = {"gen": a.gen, "accepted": True, "reason": f"accepted: pruned {len(res.dropped)} dead rule(s), scores unchanged", "commit": sha,
           "rationale": "prune (unlearning): " + ", ".join(res.dropped), "n_misses": 0,
           "val_before": {"leak_rate": res.leak_before}, "val_after": {"leak_rate": res.leak_after},
           "fp_before": {"fp_rate": res.fp_before}, "fp_after": {"fp_rate": res.fp_after}, "fp_examples": []}
    with (ROOT / "runs" / "history.jsonl").open("a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"committed {sha} as gen-{a.gen}: dropped {', '.join(res.dropped)}")


def cmd_report(a):
    hist = ROOT / "runs" / "history.jsonl"
    if not hist.exists():
        print("no runs yet"); return
    if a.markdown:
        from .report import render_markdown
        rep = ROOT / "runs" / "report.json"
        history = [json.loads(l) for l in hist.read_text().splitlines() if l.strip()]
        print(render_markdown(history, json.loads(rep.read_text()) if rep.exists() else None))
        return
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

    s = sub.add_parser("improve", help="run N self-improvement generations"); s.add_argument("--generations", type=int, default=5); s.add_argument("--start-gen", type=int, default=1); s.add_argument("--baseline-tag", default="gen-0"); s.add_argument("--data", default=str(DATA)); s.add_argument("--llm", action="store_true"); s.add_argument("--min-delta", type=float, default=0.05); s.add_argument("--max-fp", type=float, default=0.05); s.set_defaults(fn=cmd_improve)

    s = sub.add_parser("bench", help="compare systems on the same held-out data (Presidio, gen-0, current, +LLM)"); s.add_argument("--data", default=str(DATA)); s.add_argument("--set", default="heldout", choices=["train", "val", "heldout"]); s.add_argument("--baseline-tag", default="gen-0"); s.add_argument("--llm", action="store_true"); s.add_argument("--no-presidio", action="store_true"); s.add_argument("--by-technique", action="store_true"); s.set_defaults(fn=cmd_bench)

    s = sub.add_parser("prune", help="unlearning: drop rules whose removal changes no score; commit as a generation"); s.add_argument("--data", default=str(DATA)); s.add_argument("--gen", type=int, required=True); s.add_argument("--dry-run", action="store_true"); s.set_defaults(fn=cmd_prune)

    s = sub.add_parser("report", help="print generation history and held-out before/after"); s.add_argument("--markdown", action="store_true"); s.set_defaults(fn=cmd_report)

    s = sub.add_parser("serve", help="run the guard proxy"); s.add_argument("--host", default="127.0.0.1", help="use 0.0.0.0 (with GUARD_PROXY_TOKEN set) so a NemoClaw sandbox can reach it"); s.add_argument("--port", type=int, default=8787); s.add_argument("--llm", action="store_true"); s.set_defaults(fn=cmd_serve)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
