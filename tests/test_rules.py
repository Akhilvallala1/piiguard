from pathlib import Path
from piiguard.pii.rules import load_rules, luhn_ok

ROOT = Path(__file__).resolve().parents[1]

def test_loads_shipped_ruleset_with_names_and_compiled_patterns():
    rs = load_rules(ROOT / "guard" / "rules.yaml")
    names = {r.name for r in rs.rules}
    assert {"ssn", "email", "phone_us", "credit_card"} <= names
    assert all(r.regex.pattern for r in rs.rules)

def test_ssn_rule_matches_dashed_ssn():
    rs = load_rules(ROOT / "guard" / "rules.yaml")
    ssn = next(r for r in rs.rules if r.name == "ssn")
    assert ssn.regex.search("my social is 123-45-6789 ok")

def test_luhn_accepts_valid_and_rejects_invalid():
    assert luhn_ok("4111111111111111")
    assert not luhn_ok("4111111111111112")

def test_credit_card_rule_uses_luhn_validator():
    rs = load_rules(ROOT / "guard" / "rules.yaml")
    cc = next(r for r in rs.rules if r.name == "credit_card")
    assert cc.validate("4111 1111 1111 1111")
    assert not cc.validate("1234 5678 9012 3456")


import pytest
from piiguard.pii.rules import RuleSet

def test_rejects_nested_quantifier_regex_from_coach():
    with pytest.raises(ValueError, match="unsafe"):
        RuleSet.from_yaml_text("version: 1\nrules:\n  - name: x\n    pattern: '(a+)+$'\n")

def test_rejects_overlong_pattern():
    with pytest.raises(ValueError, match="too long"):
        RuleSet.from_yaml_text("version: 1\nrules:\n  - name: x\n    pattern: '" + "a" * 600 + "'\n")


def test_common_grouped_repetition_idioms_are_allowed():
    y = "version: 1\nrules:\n  - name: email\n    pattern: '[a-z0-9._%+-]+@(?:[a-z0-9-]+\\.)+[a-z]{2,}'\n  - name: spaced\n    pattern: '\\b(?:\\d[ -]?){8}\\d\\b'\n"
    rs = RuleSet.from_yaml_text(y)
    assert [r.name for r in rs.rules] == ["email", "spaced"]

def test_single_atom_nested_quantifiers_still_rejected():
    for pat in ["(a+)+", "(?:\\d*)*", "([a-z]+)*$"]:
        with pytest.raises(ValueError, match="unsafe"):
            RuleSet.from_yaml_text(f"version: 1\nrules:\n  - name: x\n    pattern: '{pat}'\n")
