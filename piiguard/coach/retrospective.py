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
    for key in ("rationale", "rules_yaml", "prompt_md"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ProposalError(f"coach proposal missing string field {key!r}")
    try:
        rules = RuleSet.from_yaml_text(data["rules_yaml"])
    except Exception as e:  # yaml or regex problems
        raise ProposalError(f"proposed rules.yaml invalid: {e}") from e
    return Proposal(data["rationale"].strip(), data["rules_yaml"], data["prompt_md"], rules)


SYSTEM = """You are the coach for a PII leak guard that protects outbound traffic from sandboxed AI agents.
The guard has two evolvable artifacts:
1. rules.yaml - regex rules (fields: name, pattern, optional validator: luhn, optional ignore_case: true). Python `re` syntax. Keep patterns short, avoid nested quantifiers like (a+)+, never exceed 400 chars per pattern.
2. prompt.md - the instruction given to a small LLM classifier that finds spans regex misses.

You will see the attacks that LEAKED through the current guard. Propose ONE focused improvement that closes the biggest class of misses without flagging ordinary text (version numbers, dates, order ids, prices, timestamps must NOT be redacted).
Return the COMPLETE new contents of both files, even if one is unchanged.

Respond with ONLY a JSON object: {"rationale": "<one or two sentences>", "rules_yaml": "<full yaml>", "prompt_md": "<full prompt>"}"""


def build_messages(misses: list[dict], rules_yaml: str, prompt_md: str, scores: dict, max_examples: int = 25) -> list[dict]:
    lines = [f"Current leak rate on training attacks: {scores.get('leak_rate', 0):.2f}"]
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
    lines.append('Return JSON with keys "rationale", "rules_yaml", "prompt_md".')
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "\n".join(lines)}]


def propose(misses: list[dict], rules_yaml: str, prompt_md: str, scores: dict, models=None, attempts: int = 3) -> Proposal:
    """Ask the coach model for a proposal; feed validation errors back and retry."""
    from ..crusoe import chat, COACH_MODEL, FALLBACK_MODEL

    messages = build_messages(misses, rules_yaml, prompt_md, scores)
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
