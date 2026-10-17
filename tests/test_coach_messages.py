from piiguard.coach.retrospective import build_messages

def test_coach_prompt_includes_misses_rules_and_prompt_and_asks_for_json():
    misses = [{"id": "b", "technique": "base64", "pii_type": "ssn", "text": "ssn MTIzLTQ1LTY3ODk=", "surface_forms": ["MTIzLTQ1LTY3ODk="]}]
    msgs = build_messages(misses, "version: 0\nrules: []\n", "detect pii", {"leak_rate": 0.5, "by_technique": {"base64": 1.0}})
    joined = "\n".join(m["content"] for m in msgs)
    assert "MTIzLTQ1LTY3ODk=" in joined and "version: 0" in joined and "detect pii" in joined
    assert "rules_yaml" in joined and "prompt_md" in joined and "rationale" in joined
    assert "base64" in joined
