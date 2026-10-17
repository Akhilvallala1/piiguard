"""Versioned regex rule set. The coach agent rewrites guard/rules.yaml between generations."""
from __future__ import annotations

import re
from dataclasses import dataclass

import regex  # drop-in superset of `re` with match timeouts; used for BOTH the safety probe and runtime scans
from pathlib import Path
from typing import Callable

import yaml


def luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


VALIDATORS: dict[str, Callable[[str], bool]] = {"luhn": luhn_ok}

MAX_PATTERN_LEN = 400
# The classic catastrophic shape: a group whose whole body is ONE unbounded-quantified atom, itself repeated:
# (a+)+, (?:\d*)*, ([a-z]+)*. Idioms like (?:[a-z0-9-]+\.)+ or (?:\d[ -]?){8} have a separator and are allowed;
# the probe-timing check below still catches anything slow in practice.
_ATOM = r"(?:\\.|\[[^\]]*\]|[^()\\\[\]|])"
_NESTED_QUANT = re.compile(r"\((?:\?:)?" + _ATOM + r"[+*]\)[+*{]")
# Adversarial probe: long runs of the things PII regexes quantify over (whitespace, digits, number words,
# fullwidth digits, separators, letters) with NO terminating match, so backtracking has to exhaust itself.
_PROBE = "\n".join([
    ("a" * 40 + "-" + "1" * 40 + "@" + "x" * 40) * 5,
    " " * 600 + "q",
    ("1 " * 300) + "q",
    ("nine " * 120) + "q",
    ("nine - " * 80) + "q",
    ("\uff11" * 300) + "q",
    ("12-" * 150) + "q",
    ("ab" * 300) + "q",
    ("%39" * 150) + "q",
])
PROBE_BUDGET_S = 0.25


def check_pattern_safe(name: str, compiled) -> None:
    """Reject patterns likely to be catastrophic. The coach is an LLM; its regexes are untrusted."""
    pattern = compiled.pattern
    if len(pattern) > MAX_PATTERN_LEN:
        raise ValueError(f"regex in rule {name!r} too long ({len(pattern)} > {MAX_PATTERN_LEN})")
    if _NESTED_QUANT.search(pattern):
        raise ValueError(f"regex in rule {name!r} is unsafe: nested quantifier")
    try:
        for _ in compiled.finditer(_PROBE, timeout=PROBE_BUDGET_S):
            pass
    except TimeoutError as e:
        raise ValueError(f"regex in rule {name!r} is unsafe: too slow on probe input") from e


@dataclass
class Rule:
    name: str
    pattern: str
    regex: "regex.Pattern | re.Pattern"
    validator: str | None = None

    def validate(self, match_text: str) -> bool:
        fn = VALIDATORS.get(self.validator or "")
        return fn(match_text) if fn else True


@dataclass
class RuleSet:
    version: int
    rules: list[Rule]
    source: str = ""

    @classmethod
    def from_yaml_text(cls, text: str) -> "RuleSet":
        data = yaml.safe_load(text) or {}
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise ValueError("rules yaml must be a mapping with a 'rules' list")
        rules: list[Rule] = []
        for raw in data["rules"]:
            if not isinstance(raw, dict) or "name" not in raw or "pattern" not in raw:
                raise ValueError(f"rule missing name/pattern: {raw!r}")
            validator = raw.get("validator")
            if validator and validator not in VALIDATORS:
                raise ValueError(f"unknown validator {validator!r} in rule {raw['name']!r}")
            flags = regex.IGNORECASE if raw.get("ignore_case") else 0
            try:
                compiled = regex.compile(raw["pattern"], flags)
            except regex.error as e:
                raise ValueError(f"invalid regex in rule {raw['name']!r}: {e}") from e
            check_pattern_safe(str(raw["name"]), compiled)
            rules.append(Rule(name=str(raw["name"]), pattern=raw["pattern"], regex=compiled, validator=validator))
        return cls(version=int(data.get("version", 0)), rules=rules, source=text)


def load_rules(path: str | Path) -> RuleSet:
    return RuleSet.from_yaml_text(Path(path).read_text())
