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


# ---- Validator toolbox. A validator receives (match_text, ruleset) and may re-run the ruleset's plain rules on a
# decoded/normalized form. This lets the coach attach a broad regex (any base64 blob) to a precise check
# (decodes to something the plain rules recognize), which keeps false positives at zero.
import base64 as _b64
import unicodedata as _ud
from urllib.parse import unquote as _unquote


def _plain_hit(text: str, ruleset) -> bool:
    if ruleset is None or not text:
        return False
    for rule in ruleset.rules:
        if rule.validator in _DECODING_VALIDATORS:
            continue  # no recursion through decoders
        for m in rule.regex.finditer(text, timeout=0.2):
            if rule.validate(m.group(0), ruleset):
                return True
    return False


def _v_luhn(s: str, ruleset=None) -> bool:
    return luhn_ok(s)


import binascii as _binascii

_DECODE_ERRORS = (ValueError, _binascii.Error, UnicodeDecodeError)  # only decode failures are swallowed; TimeoutError propagates (fail closed)


def _v_base64(s: str, ruleset=None) -> bool:
    padded = s + "=" * (-len(s) % 4)
    decoded: list[str] = []
    for fn in (_b64.b64decode, _b64.urlsafe_b64decode):
        try:
            decoded.append(fn(padded).decode("utf-8", errors="ignore"))
        except _DECODE_ERRORS:
            continue
    return any(_plain_hit(t, ruleset) for t in decoded)


def _v_hex(s: str, ruleset=None) -> bool:
    try:
        text = bytes.fromhex(s).decode("utf-8", errors="ignore")
    except _DECODE_ERRORS:
        return False
    return _plain_hit(text, ruleset)


def _v_url(s: str, ruleset=None) -> bool:
    return _plain_hit(_unquote(s), ruleset)


def _v_reversed(s: str, ruleset=None) -> bool:
    return _plain_hit(s[::-1], ruleset)


def _v_normalized(s: str, ruleset=None) -> bool:
    """Fold fullwidth digits to ASCII and strip spaces/odd separators, then try the plain rules in a few shapes."""
    folded = _ud.normalize("NFKC", s)
    digits = "".join(c for c in folded if c.isdigit())
    candidates = {folded, digits}
    if len(digits) == 9:
        candidates.add(f"{digits[:3]}-{digits[3:5]}-{digits[5:]}")      # ssn shape
    if len(digits) == 10:
        candidates.add(f"{digits[:3]}-{digits[3:6]}-{digits[6:]}")      # phone shape
    if len(digits) == 8:
        candidates.add(f"{digits[:2]}/{digits[2:4]}/{digits[4:]}")      # dob shape
    if 13 <= len(digits) <= 16:
        candidates.add(digits)                                          # card (luhn rule)
    return any(_plain_hit(c, ruleset) for c in candidates if c)


_DECODING_VALIDATORS = {"decodes_to_pii_base64", "decodes_to_pii_hex", "decodes_to_pii_url", "reversed_is_pii", "normalized_is_pii"}

VALIDATORS: dict[str, Callable] = {
    "luhn": _v_luhn,
    "decodes_to_pii_base64": _v_base64,
    "decodes_to_pii_hex": _v_hex,
    "decodes_to_pii_url": _v_url,
    "reversed_is_pii": _v_reversed,
    "normalized_is_pii": _v_normalized,
}
VALIDATOR_DOCS = {
    "luhn": "match passes the Luhn checksum (payment cards)",
    "decodes_to_pii_base64": "base64-decoding the match yields text that the plain rules flag",
    "decodes_to_pii_hex": "hex-decoding the match yields text that the plain rules flag",
    "decodes_to_pii_url": "percent-decoding the match yields text that the plain rules flag",
    "reversed_is_pii": "the reversed match is flagged by the plain rules",
    "normalized_is_pii": "after NFKC folding (fullwidth->ascii) and removing spaces/odd separators, the digits form an SSN/phone/DOB/card the plain rules flag",
}

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
    # Retry once: a busy machine (CI runner, other threads holding the GIL) can stall a fast pattern past the budget.
    # A catastrophic pattern blows the budget by orders of magnitude and fails both attempts.
    for attempt in range(2):
        try:
            for _ in compiled.finditer(_PROBE, timeout=PROBE_BUDGET_S):
                pass
            return
        except TimeoutError as e:
            if attempt == 1:
                raise ValueError(f"regex in rule {name!r} is unsafe: too slow on probe input") from e


@dataclass
class Rule:
    name: str
    pattern: str
    regex: "regex.Pattern | re.Pattern"
    validator: str | None = None

    def validate(self, match_text: str, ruleset=None) -> bool:
        fn = VALIDATORS.get(self.validator or "")
        return fn(match_text, ruleset) if fn else True


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
