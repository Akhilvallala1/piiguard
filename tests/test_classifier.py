from piiguard.pii.classifier import LLMClassifier

def test_classifier_parses_spans_and_drops_spans_not_in_text():
    def fake_chat(messages, **kw):
        assert "detect" in messages[0]["content"].lower()
        return '{"spans": [{"text": "nine one two", "type": "ssn"}, {"text": "not-present", "type": "other"}]}'
    c = LLMClassifier(chat_fn=fake_chat)
    spans = c("ssn is nine one two dash ...", "Detect PII.")
    assert spans == [{"text": "nine one two", "type": "ssn"}]

def test_classifier_returns_empty_on_garbage_output():
    c = LLMClassifier(chat_fn=lambda messages, **kw: "I cannot help with that")
    assert c("anything", "p") == []


def test_classifier_normalizes_hostile_type_strings():
    c = LLMClassifier(chat_fn=lambda messages, **kw: '{"spans": [{"text": "912-34-5678", "type": "<img src=x onerror=alert(1)>"}, {"text": "912-34-5678", "type": "Credit Card"}]}')
    spans = c("ssn 912-34-5678", "p")
    assert [s["type"] for s in spans] == ["other", "credit_card"]
