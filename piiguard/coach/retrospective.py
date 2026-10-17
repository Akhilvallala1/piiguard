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
    prompt_md: str | None   # None = keep the current prompt
    rules: RuleSet


_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$", re.MULTILINE)


def parse_proposal(text: str) -> Proposal:
    cleaned = _FENCE.sub("", text.strip()).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ProposalError("coach output contained no JSON object")
    blob = cleaned[start:end + 1]
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        try:
            data = json.loads(_repair_json(blob))
        except json.JSONDecodeError as e:
            raise ProposalError(f"coach output is not valid JSON: {e}") from e
    data = _unbackspace(data)
    if not isinstance(data.get("rationale"), str) or not data["rationale"].strip():
        raise ProposalError("coach proposal missing string field 'rationale'")
    prompt_md = data.get("prompt_md")
    if prompt_md is not None and (not isinstance(prompt_md, str) or not prompt_md.strip()):
        prompt_md = None
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
    return Proposal(data["rationale"].strip(), rules_yaml, prompt_md, rules)


_ESCAPE_PAIR = re.compile(r'\\(["\\/bfnrtu])|\\')   # legal escape pair, or a lone backslash
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _repair_json(blob: str) -> str:
    """Fix what LLMs reliably get wrong in JSON: regex escapes like \d and trailing commas.
    \b is a legal JSON escape (backspace), so a regex word boundary survives as 0x08; _unbackspace restores it."""
    fixed = _ESCAPE_PAIR.sub(lambda m: m.group(0) if m.group(1) else chr(92) * 2, blob)
    fixed = _TRAILING_COMMA.sub(r"\1", fixed)
    return fixed


def _unbackspace(obj):
    if isinstance(obj, str):
        return obj.replace(chr(8), chr(92) + 'b')
    if isinstance(obj, list):
        return [_unbackspace(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _unbackspace(v) for k, v in obj.items()}
    return obj


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
1. RULES: a list of regex rules, each {"name": str, "pattern": str, "validator": <name> (optional), "ignore_case": true (optional)}.
   Python `re` syntax. Patterns are matched with finditer on raw text. Keep patterns short, no nested quantifiers like (a+)+, max 400 chars.
   The pattern must match the ENCODED surface form exactly as it appears in the text (e.g. a base64 blob, spaced digits, fullwidth digits).
   VALIDATORS let a broad pattern stay precise: the match is kept only if the validator passes. Available validators:
   __VALIDATOR_DOCS__
   Pattern: use a broad shape regex (e.g. any base64-looking token of 12+ chars) + the matching validator, so clean text is never flagged.
   Domain identifiers (badge, claim, policy, member, case numbers) almost always have a fixed prefix and digit grouping, e.g. 'ADJ-48213-TX',
   'CLM-2026-0048213', 'POL 88-4421-7730'. Anchor on the prefix and the exact groups. Never use a generic "any id-like token" rule: order numbers,
   SKUs, flight numbers, commit hashes and PR numbers in clean traffic look like ids too.
2. PROMPT: the instruction given to a small LLM classifier that finds spans regex misses. It only matters when the classifier is ENABLED.

You will see the attacks that LEAKED through the current guard, plus the outcome of previous proposals. Propose ONE focused improvement
that closes the biggest remaining class of misses WITHOUT flagging ordinary text (version numbers, dates like 2026-10-17, order ids,
prices, timestamps, ports, commit hashes must NOT be redacted). Do not repeat an idea that was already rejected. Keep every existing rule
unless you are deliberately replacing it with a better one. Return the COMPLETE rule list and the COMPLETE prompt.

Respond with ONLY a JSON object: {"rationale": "<one or two sentences>", "rules": [ {...}, ... ], "prompt_md": "<full prompt, or omit to keep current>"}"""

from ..pii.rules import VALIDATOR_DOCS as _VD
SYSTEM = SYSTEM.replace("__VALIDATOR_DOCS__", "\n   ".join(f"- {k}: {v}" for k, v in _VD.items()))


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
            for ex in (h.get("fp_examples") or [])[:4]:
                lines.append(f"    false positive: rule {ex['rule']!r} flagged {ex['value']!r} in clean text {ex['text']!r}")
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
