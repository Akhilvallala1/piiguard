import subprocess
from pathlib import Path
from piiguard.prune import prune_rules

RULES = """version: 3
rules:
  - name: ssn
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
  - name: ssn_dup
    pattern: '\\d{3}-\\d{2}-\\d{4}'
  - name: never_fires
    pattern: 'zzzz9999qqqq'
  - name: b64
    pattern: 'OTEyLTM0LTU2Nzg='
"""
ATTACKS = [
    {"id": "a", "technique": "plain", "pii_type": "ssn", "text": "ssn 912-34-5678", "surface_forms": ["912-34-5678"]},
    {"id": "b", "technique": "base64", "pii_type": "ssn", "text": "ssn OTEyLTM0LTU2Nzg=", "surface_forms": ["OTEyLTM0LTU2Nzg="]},
]
CLEAN = ["hello there", "order 48213"]

def test_prune_drops_rules_whose_removal_changes_nothing_and_keeps_the_rest():
    result = prune_rules(RULES, ATTACKS, CLEAN)
    kept = [r["name"] for r in result.kept]
    assert "never_fires" in result.dropped
    assert "b64" in kept                     # removing it would leak attack b
    assert result.leak_before == result.leak_after and result.fp_before == result.fp_after
    assert "never_fires" not in result.rules_yaml

def test_prune_removes_only_one_of_two_redundant_rules():
    result = prune_rules(RULES, ATTACKS, CLEAN)
    names = [r["name"] for r in result.kept]
    assert sum(n in names for n in ("ssn", "ssn_dup")) == 1
