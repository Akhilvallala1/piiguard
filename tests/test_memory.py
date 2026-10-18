from pathlib import Path
from piiguard.memory import signature, ShapeLedger
from piiguard.pii.guard import Guard

RULES_A = "version: 1\nrules:\n  - name: ssn\n    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'\n  - name: badge\n    pattern: '\\bADJ-\\d{5}-[A-Z]{2}\\b'\n"
RULES_B = "version: 2\nrules:\n  - name: ssn\n    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'\n"   # badge rule dropped

ATTACKS = [
    {"id": "a", "technique": "plain", "pii_type": "ssn", "text": "ssn 912-34-5678", "surface_forms": ["912-34-5678"]},
    {"id": "b", "technique": "plain", "pii_type": "adjuster_badge", "text": "badge ADJ-48213-TX", "surface_forms": ["ADJ-48213-TX"]},
    {"id": "c", "technique": "base64", "pii_type": "ssn", "text": "x OTEyLTM0LTU2Nzg=", "surface_forms": ["OTEyLTM0LTU2Nzg="]},
]

def test_signature_keeps_shape_not_content():
    assert signature("ADJ-48213-TX") == "AAA-99999-AA"
    assert signature("CLM-2026-0048213") == "AAA-9999-9999999"
    assert signature("912-34-5678") == signature("923-45-6789")
    assert signature("maria.chen@example.com") == "AAAAA.AAAA@AAAAAAA.AAA"

def test_ledger_records_caught_shapes_with_rule_and_generation(tmp_path):
    led = ShapeLedger(tmp_path / "shapes.jsonl")
    n = led.record(Guard.from_texts(RULES_A), ATTACKS, gen=1)
    assert n == 2                                   # ssn and badge caught; base64 not
    assert {e["rule"] for e in led.entries} == {"ssn", "badge"}
    assert all(e["gen"] == 1 for e in led.entries)

def test_regressions_detect_shapes_a_candidate_stops_catching(tmp_path):
    led = ShapeLedger(tmp_path / "shapes.jsonl")
    led.record(Guard.from_texts(RULES_A), ATTACKS, gen=1)
    lost = led.regressions(Guard.from_texts(RULES_B))
    assert [e["surface"] for e in lost] == ["ADJ-48213-TX"]
    assert led.regressions(Guard.from_texts(RULES_A)) == []

def test_precedents_rank_by_shape_similarity(tmp_path):
    led = ShapeLedger(tmp_path / "shapes.jsonl")
    led.record(Guard.from_texts(RULES_A), ATTACKS, gen=1)
    top = led.precedents("ADJ-50977-CA", k=1)
    assert top[0]["surface"] == "ADJ-48213-TX" and top[0]["rule"] == "badge" and top[0]["score"] > 0.9
    assert led.precedents("totally unrelated words", k=1)[0]["score"] < 0.3

def test_ledger_persists_across_instances(tmp_path):
    p = tmp_path / "shapes.jsonl"
    ShapeLedger(p).record(Guard.from_texts(RULES_A), ATTACKS, gen=1)
    assert len(ShapeLedger(p).entries) == 2


def test_long_text_shapes_are_still_checked_and_a_broken_entry_counts_as_regression(tmp_path):
    led = ShapeLedger(tmp_path / "s.jsonl")
    long_attack = {"id": "L", "technique": "plain", "pii_type": "ssn", "text": ("filler words " * 40) + "ssn 912-34-5678", "surface_forms": ["912-34-5678"]}
    assert led.record(Guard.from_texts(RULES_A), [long_attack], gen=1) == 1
    assert led.regressions(Guard.from_texts(RULES_A)) == []            # the full text is stored, so it is checked
    led.entries.append({"surface": "ADJ-99999-ZZ", "signature": "AAA-99999-AA", "rule": "badge", "gen": 1, "text": "text that lacks the surface"})
    assert any(e["surface"] == "ADJ-99999-ZZ" for e in led.regressions(Guard.from_texts(RULES_A)))   # cannot verify -> regression


def test_timeout_findings_never_count_as_a_catch(tmp_path):
    from piiguard.pii.rules import Rule
    class Hang:
        pattern = "x"
        def finditer(self, text, timeout=None): raise TimeoutError()
    g = Guard.from_texts(RULES_A); g.rules.rules.insert(0, Rule(name="hang", pattern="x", regex=Hang()))
    led = ShapeLedger(tmp_path / "s.jsonl")
    assert led.record(g, ATTACKS, gen=1) == 0                          # a scan that times out attributes nothing
    led2 = ShapeLedger(tmp_path / "s2.jsonl"); led2.record(Guard.from_texts(RULES_A), ATTACKS, gen=1)
    assert len(led2.regressions(g)) == len(led2.entries)              # a candidate that times out regresses everything
