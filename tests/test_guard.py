from pathlib import Path
from piiguard.pii.guard import Guard

ROOT = Path(__file__).resolve().parents[1]

def make_guard():
    return Guard.from_dir(ROOT / "guard")

def test_redact_replaces_ssn_with_typed_token_and_restore_round_trips():
    g = make_guard()
    text = "Customer SSN 123-45-6789, email a.b@example.com"
    red = g.redact(text)
    assert "123-45-6789" not in red.text
    assert "a.b@example.com" not in red.text
    assert "[PII_SSN_1]" in red.text and "[PII_EMAIL_1]" in red.text
    assert g.restore(red.text, red.mapping) == text

def test_clean_text_is_unchanged_and_has_no_findings():
    g = make_guard()
    text = "Please summarize the Q3 roadmap in three bullets."
    red = g.redact(text)
    assert red.text == text
    assert red.findings == []

def test_same_value_twice_gets_same_token():
    g = make_guard()
    red = g.redact("call 555-123-4567 or 555-123-4567")
    assert red.text.count("[PII_PHONE_US_1]") == 2
    assert len(red.mapping) == 1
