from piiguard.redteam.carriers import llm_carrier

def test_llm_carrier_returns_template_with_pii_placeholder():
    fake = lambda messages, **kw: 'Agent note for {name}: the {label} on file is {pii}, please verify.'
    t = llm_carrier("base64", "ssn", {"name": "Maria Chen"}, chat_fn=fake)
    assert "{pii}" in t

def test_llm_carrier_raises_when_model_forgets_placeholder():
    import pytest
    with pytest.raises(ValueError):
        llm_carrier("base64", "ssn", {"name": "Maria Chen"}, chat_fn=lambda messages, **kw: "no placeholder here")
