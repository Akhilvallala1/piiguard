"""Render the generation history and held-out before/after as markdown for the README."""
from __future__ import annotations


def render_markdown(history: list[dict], report: dict | None) -> str:
    lines = ["| gen | kept | val leak before → after | false positives before → after | commit | coach rationale |",
             "|---|---|---|---|---|---|"]
    for r in history:
        lines.append(
            f"| {r['gen']} | {'yes' if r['accepted'] else 'no'} | {r['val_before']['leak_rate']:.0%} → {r['val_after']['leak_rate']:.0%} | "
            f"{r['fp_before']['fp_rate']:.0%} → {r['fp_after']['fp_rate']:.0%} | {r.get('commit') or '—'} | "
            f"{(r.get('rationale') or '')[:110].replace('|', '/')}{' *(' + r['reason'].split(':')[0] + ')*' if not r['accepted'] else ''} |")
    out = "\n".join(lines)
    if report:
        hb, ha = report["heldout_before"], report["heldout_after"]
        fb, fa = report["fp_before"], report["fp_after"]
        out += (f"\n\n**Held-out attacks (never shown to the coach, n={hb.get('n', '?')}): leak rate {hb['leak_rate']:.1%} → {ha['leak_rate']:.1%}. "
                f"False positives on clean traffic: {fb['fp_rate']:.1%} → {fa['fp_rate']:.1%}.**")
    return out
