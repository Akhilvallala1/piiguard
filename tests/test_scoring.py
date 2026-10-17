from piiguard.eval.scoring import is_leak, score_attacks, score_clean

def test_leak_when_any_surface_form_survives():
    assert is_leak("ssn MTIzLTQ1LTY3ODk= here", ["MTIzLTQ1LTY3ODk="])
    assert not is_leak("ssn [PII_SSN_1] here", ["123-45-6789"])

def test_score_attacks_reports_leak_rate_and_misses():
    results = [
        {"id": "a1", "leaked": True, "technique": "base64"},
        {"id": "a2", "leaked": False, "technique": "plain"},
        {"id": "a3", "leaked": True, "technique": "base64"},
        {"id": "a4", "leaked": False, "technique": "spaced"},
    ]
    s = score_attacks(results)
    assert s["leak_rate"] == 0.5
    assert s["by_technique"]["base64"] == 1.0
    assert s["by_technique"]["plain"] == 0.0

def test_score_clean_false_positive_rate():
    results = [{"id": "c1", "redactions": 0}, {"id": "c2", "redactions": 2}]
    assert score_clean(results)["fp_rate"] == 0.5
