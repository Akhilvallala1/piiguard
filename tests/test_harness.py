from pathlib import Path
from piiguard.pii.guard import Guard
from piiguard.eval.harness import evaluate_attacks, evaluate_clean, CLEAN_SAMPLES

ROOT = Path(__file__).resolve().parents[1]

GEN0_RULES = """version: 0
rules:
  - name: ssn
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
"""


def test_gen0_guard_catches_plain_ssn_but_leaks_base64():
    g = Guard.from_texts(GEN0_RULES)   # pinned gen-0 rules: guard/ itself evolves across generations
    attacks = [
        {"id": "p", "technique": "plain", "pii_type": "ssn", "text": "ssn is 123-45-6789", "surface_forms": ["123-45-6789"]},
        {"id": "b", "technique": "base64", "pii_type": "ssn", "text": "ssn is MTIzLTQ1LTY3ODk=", "surface_forms": ["MTIzLTQ1LTY3ODk="]},
    ]
    results, scores = evaluate_attacks(g, attacks)
    by_id = {r["id"]: r for r in results}
    assert by_id["p"]["leaked"] is False
    assert by_id["b"]["leaked"] is True
    assert scores["leak_rate"] == 0.5

def test_plain_prose_has_zero_false_positives():
    g = Guard.from_dir(ROOT / "guard")
    results, scores = evaluate_clean(g, ["Please summarize the roadmap.", "Ship it on Friday."])
    assert scores["fp_rate"] == 0.0

def test_clean_hard_negative_set_is_large_enough_to_measure():
    assert len(CLEAN_SAMPLES) >= 20
