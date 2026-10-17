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
