"""The guard: scan text for PII, redact to reversible tokens, restore on the way back."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .rules import RuleSet, load_rules

# A classifier takes (text, prompt) and returns [{"text": str, "type": str}, ...]
Classifier = Callable[[str, str], list[dict]]

SCAN_TIMEOUT_S = 0.5  # per rule per string; on timeout the whole string is withheld (fail closed)


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

    @classmethod
    def from_texts(cls, rules_yaml: str, prompt: str = "", classifier: Optional[Classifier] = None) -> "Guard":
        return cls(RuleSet.from_yaml_text(rules_yaml), prompt, classifier)

    def scan(self, text: str, use_classifier: bool = True) -> list[Finding]:
        found: list[Finding] = []
        for rule in self.rules.rules:
            try:
                for m in rule.regex.finditer(text, timeout=SCAN_TIMEOUT_S):
                    if rule.validate(m.group(0), self.rules):
                        found.append(Finding(rule.name, m.group(0), m.start(), m.end(), "regex"))
            except TimeoutError:
                # Pathological input vs. a rule: never let it through unscanned.
                return [Finding("scan_timeout", text, 0, len(text), "timeout")]
        if use_classifier and self.classifier is not None:
            try:
                spans = self.classifier(text, self.prompt, regex_findings=list(found))
            except TypeError:  # plain classifiers take (text, prompt)
                spans = self.classifier(text, self.prompt)
            for span in spans:
                value = str(span.get("text", ""))
                if not value:
                    continue
                start = text.find(value)
                while start != -1:
                    found.append(Finding(str(span.get("type", "other")), value, start, start + len(value), "llm"))
                    start = text.find(value, start + 1)
        return _merge_overlaps(found)

    def redact(self, text: str) -> Redaction:
        return self.session().redact(text)

    def session(self) -> "RedactionSession":
        """One session per outbound request: tokens stay unique and the mapping is shared across all strings."""
        return RedactionSession(self)

    @staticmethod
    def restore(text: str, mapping: dict[str, str]) -> str:
        for token, value in mapping.items():
            text = text.replace(token, value)
        return text


class RedactionSession:
    def __init__(self, guard: "Guard"):
        self.guard = guard
        self.mapping: dict[str, str] = {}
        self.findings: list[Finding] = []
        self._value_to_token: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def redact(self, text: str) -> Redaction:
        findings = self.guard.scan(text)
        out: list[str] = []
        cursor = 0
        local: dict[str, str] = {}
        for f in findings:
            value = text[f.start:f.end]
            token = self._value_to_token.get(value)
            if token is None:
                self._counters[f.type] = self._counters.get(f.type, 0) + 1
                token = f"[PII_{f.type.upper()}_{self._counters[f.type]}]"
                self._value_to_token[value] = token
                self.mapping[token] = value
            local[token] = value
            out.append(text[cursor:f.start])
            out.append(token)
            cursor = f.end
        out.append(text[cursor:])
        self.findings.extend(findings)
        return Redaction("".join(out), local, findings)


def _merge_overlaps(findings: list[Finding]) -> list[Finding]:
    """Merge overlapping spans into their union so no partial value survives; sorted by start."""
    findings = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    merged: list[Finding] = []
    for f in findings:
        if merged and f.start < merged[-1].end:
            last = merged[-1]
            if f.end > last.end:
                last.end = f.end
            continue
        merged.append(Finding(f.type, f.value, f.start, f.end, f.source))
    return merged
