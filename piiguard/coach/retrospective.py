"""The coach: reads the guard's misses and proposes a new rules.yaml + prompt.md."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..pii.rules import RuleSet


class ProposalError(ValueError):
    pass


@dataclass
class Proposal:
    rationale: str
    rules_yaml: str
    prompt_md: str
    rules: RuleSet


_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$", re.MULTILINE)


def parse_proposal(text: str) -> Proposal:
    cleaned = _FENCE.sub("", text.strip()).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ProposalError("coach output contained no JSON object")
    try:
        data = json.loads(cleaned[start:end + 1])
    except json.JSONDecodeError as e:
        raise ProposalError(f"coach output is not valid JSON: {e}") from e
    for key in ("rationale", "prompt_md"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ProposalError(f"coach proposal missing string field {key!r}")
    if isinstance(data.get("rules"), list):
        rules_yaml = rules_to_yaml(data["rules"], version=int(data.get("version", 0) or 0))
    elif isinstance(data.get("rules_yaml"), str) and data["rules_yaml"].strip():
        rules_yaml = data["rules_yaml"]
    else:
        raise ProposalError("coach proposal needs a 'rules' list")
    try:
        rules = RuleSet.from_yaml_text(rules_yaml)
    except Exception as e:  # yaml or regex problems
        raise ProposalError(f"proposed rules invalid: {e}") from e
    return Proposal(data["rationale"].strip(), rules_yaml, data["prompt_md"], rules)


def rules_to_yaml(rules: list, version: int = 0) -> str:
    """Serialize rules ourselves with single-quoted patterns: no YAML escaping hazards for the coach to trip on."""
    import yaml
    clean = []
    for r in rules:
        if not isinstance(r, dict) or not r.get("name") or not r.get("pattern"):
            raise ProposalError(f"rule missing name/pattern: {r!r}")
        item = {"name": str(r["name"]), "pattern": str(r["pattern"])}
        if r.get("validator"):
            item["validator"] = str(r["validator"])
        if r.get("ignore_case"):
            item["ignore_case"] = True
        clean.append(item)
    return yaml.safe_dump({"version": version, "rules": clean}, default_style="'", sort_keys=False, allow_unicode=True, width=1000)


SYSTEM = """You are the coach for a PII leak guard that protects outbound traffic from sandboxed AI agents.
The guard has two evolvable artifacts:
1. RULES: a list of regex rules, each {"name": str, "pattern": str, "validator": "luhn" (optional), "ignore_case": true (optional)}.
   Python `re` syntax. Patterns are matched with re.finditer on raw text. Keep patterns short, no nested quantifiers like (a+)+, max 400 chars.
   The pattern must match the ENCODED surface form exactly as it appears in the text (e.g. a base64 blob, spaced digits, fullwidth digits).
2. PROMPT: the instruction given to a small LLM classifier that finds spans regex misses. It only matters when the classifier is ENABLED.

You will see the attacks that LEAKED through the current guard, plus the outcome of previous proposals. Propose ONE focused improvement
that closes the biggest remaining class of misses WITHOUT flagging ordinary text (version numbers, dates like 2026-10-17, order ids,
prices, timestamps, ports, commit hashes must NOT be redacted). Do not repeat an idea that was already rejected. Keep every existing rule
unless you are deliberately replacing it with a better one. Return the COMPLETE rule list and the COMPLETE prompt.

Respond with ONLY a JSON object: {"rationale": "<one or two sentences>", "rules": [ {...}, ... ], "prompt_md": "<full prompt>"}"""


def build_messages(misses: list[dict], rules_yaml: str, prompt_md: str, scores: dict, max_examples: int = 25,
                   classifier_enabled: bool = False, history: list[dict] | None = None) -> list[dict]:
    mode = ("LLM classifier is ENABLED: both the rules and the prompt matter." if classifier_enabled
            else "LLM classifier is DISABLED for this run: ONLY the rules can change the score. Prompt edits are wasted; return the prompt unchanged.")
    lines = [mode, f"Current leak rate on training attacks: {scores.get('leak_rate', 0):.2f}"]
    if history:
        lines.append("")
        lines.append("PREVIOUS PROPOSALS (do not repeat rejected ideas):")
        for h in history[-6:]:
            lines.append(f"- gen {h.get('gen')}: {'ACCEPTED' if h.get('accepted') else 'REJECTED'} - {h.get('rationale', '')[:160]} -> {h.get('reason', '')}")
    by_t = scores.get("by_technique") or {}
    if by_t:
        lines.append("Leak rate by technique: " + ", ".join(f"{t}={v:.2f}" for t, v in by_t.items()))
    lines.append("")
    lines.append(f"LEAKED ATTACKS ({min(len(misses), max_examples)} of {len(misses)} shown). The surface form is the exact substring that must be caught:")
    for m in misses[:max_examples]:
        lines.append(f"- id={m['id']} technique={m.get('technique')} pii_type={m.get('pii_type')} surface_forms={m.get('surface_forms')}\n  text: {m['text']!r}")
    lines.append("")
    lines.append("CURRENT rules.yaml:\n```yaml\n" + rules_yaml.rstrip() + "\n```")
    lines.append("CURRENT prompt.md:\n```\n" + prompt_md.rstrip() + "\n```")
    lines.append("")
    lines.append('Return JSON with keys "rationale", "rules" (full list), "prompt_md" (full text).')
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "\n".join(lines)}]


def propose(misses: list[dict], rules_yaml: str, prompt_md: str, scores: dict, models=None, attempts: int = 3,
            classifier_enabled: bool = False, history: list[dict] | None = None) -> Proposal:
    """Ask the coach model for a proposal; feed validation errors back and retry."""
    from ..crusoe import chat, COACH_MODEL, FALLBACK_MODEL

    messages = build_messages(misses, rules_yaml, prompt_md, scores, classifier_enabled=classifier_enabled, history=history)
    last: Exception | None = None
    for _ in range(attempts):
        raw = chat(messages, models=models or [COACH_MODEL, FALLBACK_MODEL], json_mode=True, max_tokens=6000, temperature=0.3)
        try:
            return parse_proposal(raw)
        except ProposalError as e:
            last = e
            messages = messages + [{"role": "assistant", "content": raw}, {"role": "user", "content": f"That proposal was rejected: {e}. Fix it and return the full JSON again."}]
    assert last is not None
    raise last
