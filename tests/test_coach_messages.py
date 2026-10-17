from piiguard.coach.retrospective import build_messages

def test_coach_prompt_includes_misses_rules_and_prompt_and_asks_for_json():
    misses = [{"id": "b", "technique": "base64", "pii_type": "ssn", "text": "ssn MTIzLTQ1LTY3ODk=", "surface_forms": ["MTIzLTQ1LTY3ODk="]}]
    msgs = build_messages(misses, "version: 0\nrules: []\n", "detect pii", {"leak_rate": 0.5, "by_technique": {"base64": 1.0}})
    joined = "\n".join(m["content"] for m in msgs)
    assert "MTIzLTQ1LTY3ODk=" in joined and "version: 0" in joined and "detect pii" in joined
    assert "\"rules\"" in joined and "prompt_md" in joined and "rationale" in joined
    assert "base64" in joined


def test_coach_is_told_when_classifier_is_disabled_and_sees_history():
    history = [{"gen": 1, "accepted": False, "rationale": "tweak the prompt", "reason": "rejected: leak rate only improved by 0.00"}]
    msgs = build_messages([], "version: 0\nrules: []\n", "p", {"leak_rate": 0.7}, classifier_enabled=False, history=history)
    joined = "\n".join(m["content"] for m in msgs)
    assert "DISABLED" in joined and "rules" in joined
    assert "tweak the prompt" in joined and "rejected" in joined


def test_coach_is_told_when_classifier_is_enabled():
    msgs = build_messages([], "version: 0\nrules: []\n", "p", {"leak_rate": 0.7}, classifier_enabled=True)
    assert "ENABLED" in "\n".join(m["content"] for m in msgs)
