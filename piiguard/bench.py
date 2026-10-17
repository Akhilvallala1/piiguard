"""Benchmark: the same held-out attacks and clean samples through several systems, one row each.
Systems are plain callables text -> redacted text, so anything can be compared (Presidio, a frozen gen-0, us)."""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .eval.scoring import is_leak, score_attacks, score_clean

Redactor = Callable[[str], str]


def run_bench(systems: dict[str, Redactor], attacks: list[dict], clean: list[str]) -> list[dict]:
    rows = []
    workers = max(1, int(os.environ.get("PIIGUARD_WORKERS", "6")))
    for name, fn in systems.items():
        t0 = time.perf_counter()
        with ThreadPoolExecutor(workers) as ex:
            red_attacks = list(ex.map(fn, [a["text"] for a in attacks]))
            red_clean = list(ex.map(fn, clean))
        ms_per_text = 1000 * (time.perf_counter() - t0) / max(1, len(attacks) + len(clean))
        a_res = [{"id": a["id"], "technique": a.get("technique"), "leaked": is_leak(out, a["surface_forms"])} for a, out in zip(attacks, red_attacks)]
        c_res = [{"id": f"c{i}", "redactions": 0 if out == text else 1} for i, (text, out) in enumerate(zip(clean, red_clean))]
        s, c = score_attacks(a_res), score_clean(c_res)
        rows.append({"system": name, "leak_rate": s["leak_rate"], "leaks": s["leaks"], "n": s["n"], "fp_rate": c["fp_rate"],
                     "by_technique": s["by_technique"], "ms_per_text": round(ms_per_text, 1)})
    return rows


def presidio_redactor(score_threshold: float = 0.35, entities: list[str] | None = None) -> Redactor:
    """Microsoft Presidio with its default recognizers and the spaCy large English model."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine

    try:
        provider = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]})
        analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
    except Exception:  # noqa: BLE001 - fall back to whatever model presidio finds
        analyzer = AnalyzerEngine()
    anonymizer = AnonymizerEngine()

    def redact(text: str) -> str:
        results = analyzer.analyze(text=text, language="en", score_threshold=score_threshold, entities=entities)
        if not results:
            return text
        return anonymizer.anonymize(text=text, analyzer_results=results).text

    return redact


def render_table(rows: list[dict]) -> str:
    lines = ["| system | held-out leak rate | false positives | ms/text |", "|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['system']} | {r['leak_rate']:.1%} ({r['leaks']}/{r['n']}) | {r['fp_rate']:.1%} | {r.get('ms_per_text', 0):.0f} |")
    return "\n".join(lines)
