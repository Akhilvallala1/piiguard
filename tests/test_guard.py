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


from piiguard.pii.guard import Finding, _merge_overlaps

def test_overlapping_findings_are_merged_into_union_span_not_dropped():
    a = Finding("phone_us", "0123456789", 0, 10, "regex")
    b = Finding("credit_card", "56789012345", 5, 16, "regex")
    merged = _merge_overlaps([a, b])
    assert len(merged) == 1
    assert (merged[0].start, merged[0].end) == (0, 16)

def test_redaction_of_overlap_removes_both_values_from_text():
    g = make_guard()
    # llm classifier says the whole phrase is a name-like span overlapping the regex ssn hit
    g.classifier = lambda text, prompt: [{"text": "Maria 912-34", "type": "name"}]
    red = g.redact("Maria 912-34-5678 called")
    assert "912-34-5678" not in red.text and "Maria" not in red.text
    assert red.text.endswith(" called")


def test_scan_fails_closed_when_a_rule_times_out():
    from piiguard.pii.rules import Rule
    class Hang:
        pattern = "x"
        def finditer(self, text, timeout=None):
            raise TimeoutError("regex timeout")
    g = make_guard()
    g.rules.rules.append(Rule(name="hang", pattern="x", regex=Hang()))
    red = g.redact("Customer note with 912-34-5678 inside")
    assert red.text == "[PII_SCAN_TIMEOUT_1]"            # whole string withheld, nothing leaks
    assert red.mapping["[PII_SCAN_TIMEOUT_1]"] == "Customer note with 912-34-5678 inside"


def test_guard_from_texts_builds_without_files():
    from piiguard.pii.guard import Guard
    g = Guard.from_texts("version: 3\nrules:\n  - name: ssn\n    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'\n", "p")
    assert g.rules.version == 3 and g.redact("x 912-34-5678").text == "x [PII_SSN_1]"
