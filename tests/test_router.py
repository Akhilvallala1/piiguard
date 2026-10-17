from piiguard.pii.router import complexity, route, RoutedClassifier
from piiguard.pii.guard import Finding

def test_plain_prose_with_nothing_suspicious_skips_the_model():
    c = complexity("Please summarize the Q3 roadmap in three bullets.", [])
    assert c["score"] == 0 and route(c) == "skip"

def test_residual_signals_route_to_the_small_model():
    text = "ssn is nine five six dash seven eight dash nine zero one two"
    c = complexity(text, [])
    assert "number_words" in c["signals"] and route(c) == "small"

def test_many_signals_or_long_text_route_to_the_large_model():
    text = ("Adjuster badge ADJ-48213-TX, claim CLM-2026-0048213, token MTIzNC01Njc4LTkwMTItMzQ1Ng==, hex 3931322d33342d35363738, "
            "％39％31％32, ９１２－３４, call nine one two, dob and passport and license on file. ") * 3
    c = complexity(text, [])
    assert route(c) == "large"

def test_regex_findings_remove_their_signal():
    text = "Customer SSN 912-34-5678 is asking about the roadmap."
    with_finding = complexity(text, [Finding("ssn", "912-34-5678", 13, 24, "regex")])
    without = complexity(text, [])
    assert with_finding["score"] < without["score"]

def test_routed_classifier_uses_the_right_model_and_reports_it():
    calls = []
    def small(messages, **kw): calls.append("small"); return '{"spans": [{"text": "nine one two", "type": "ssn"}]}'
    def large(messages, **kw): calls.append("large"); return '{"spans": []}'
    rc = RoutedClassifier(small_chat=small, large_chat=large)
    assert rc("Please summarize the roadmap.", "p") == [] and rc.last["route"] == "skip" and calls == []
    assert rc("ssn is nine one two dash", "p") == [{"text": "nine one two", "type": "ssn"}] and rc.last["route"] == "small"
    long = ("badge ADJ-1, claim CLM-2, MTIzNC01Njc4LTkwMTItMzQ1Ng==, 3931322d33342d35363738, ％39％31, ９１２, nine one two, passport license dob. ") * 3
    rc(long, "p"); assert rc.last["route"] == "large" and calls[-1] == "large"


def test_long_zero_signal_text_still_sees_the_small_model():
    text = ("Please summarize the quarterly roadmap and the hiring plan for the platform team in a few bullets. " * 3)
    c = complexity(text, [])
    assert c["score"] == 0 and route(c) == "small"   # skipping is only allowed for short structural strings


def test_routed_classifier_reports_cache_hits():
    calls = []
    def small(messages, **kw): calls.append(1); return '{"spans": [{"text": "nine one two", "type": "ssn"}]}'
    rc = RoutedClassifier(small_chat=small, large_chat=small)
    rc("ssn is nine one two dash", "p"); first = dict(rc.last)
    rc("ssn is nine one two dash", "p"); second = dict(rc.last)
    assert first["cached"] is False and second["cached"] is True and len(calls) == 1
