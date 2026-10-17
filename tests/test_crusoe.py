from piiguard.crusoe import chat_with_fallback

class _Boom(Exception):
    pass

def test_falls_back_to_second_model_after_primary_fails():
    calls = []
    def fake_call(model, messages, **kw):
        calls.append(model)
        if model == "primary":
            raise _Boom("503")
        return "ok from " + model
    out = chat_with_fallback(fake_call, ["primary", "backup"], [{"role": "user", "content": "hi"}], retries=1, backoff=0)
    assert out == "ok from backup"
    assert calls == ["primary", "backup"]

def test_retries_same_model_before_falling_back():
    calls = []
    def flaky(model, messages, **kw):
        calls.append(model)
        if len(calls) < 2:
            raise _Boom("429")
        return "ok"
    assert chat_with_fallback(flaky, ["primary", "backup"], [], retries=2, backoff=0) == "ok"
    assert calls == ["primary", "primary"]
