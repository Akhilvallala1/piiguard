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
