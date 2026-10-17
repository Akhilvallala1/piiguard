"""The guard: scan text for PII, redact to reversible tokens, restore on the way back."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .rules import RuleSet, load_rules

# A classifier takes (text, prompt) and returns [{"text": str, "type": str}, ...]
Classifier = Callable[[str, str], list[dict]]


@dataclass
class Finding:
    type: str
    value: str
    start: int
    end: int
    source: str  # "regex" | "llm"


@dataclass
class Redaction:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)  # token -> original value
    findings: list[Finding] = field(default_factory=list)


class Guard:
    def __init__(self, rules: RuleSet, prompt: str = "", classifier: Optional[Classifier] = None):
        self.rules = rules
        self.prompt = prompt
        self.classifier = classifier

    @classmethod
    def from_dir(cls, path: str | Path, classifier: Optional[Classifier] = None) -> "Guard":
        path = Path(path)
        prompt_file = path / "prompt.md"
        prompt = prompt_file.read_text() if prompt_file.exists() else ""
        return cls(load_rules(path / "rules.yaml"), prompt, classifier)

    def scan(self, text: str) -> list[Finding]:
        found: list[Finding] = []
        for rule in self.rules.rules:
            for m in rule.regex.finditer(text):
                if rule.validate(m.group(0)):
                    found.append(Finding(rule.name, m.group(0), m.start(), m.end(), "regex"))
        if self.classifier is not None:
            for span in self.classifier(text, self.prompt):
                value = str(span.get("text", ""))
                if not value:
                    continue
                start = text.find(value)
                while start != -1:
                    found.append(Finding(str(span.get("type", "other")), value, start, start + len(value), "llm"))
                    start = text.find(value, start + 1)
        return _dedupe_overlaps(found)

    def redact(self, text: str) -> Redaction:
        findings = self.scan(text)
        mapping: dict[str, str] = {}
        value_to_token: dict[str, str] = {}
        counters: dict[str, int] = {}
        out: list[str] = []
        cursor = 0
        for f in findings:
            token = value_to_token.get(f.value)
            if token is None:
                counters[f.type] = counters.get(f.type, 0) + 1
                token = f"[PII_{f.type.upper()}_{counters[f.type]}]"
                value_to_token[f.value] = token
                mapping[token] = f.value
            out.append(text[cursor:f.start])
            out.append(token)
            cursor = f.end
        out.append(text[cursor:])
        return Redaction("".join(out), mapping, findings)

    @staticmethod
    def restore(text: str, mapping: dict[str, str]) -> str:
        for token, value in mapping.items():
            text = text.replace(token, value)
        return text


def _dedupe_overlaps(findings: list[Finding]) -> list[Finding]:
    """Keep longest match when spans overlap; return sorted by start."""
    findings = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    kept: list[Finding] = []
    last_end = -1
    for f in findings:
        if f.start >= last_end:
            kept.append(f)
            last_end = f.end
    return kept
