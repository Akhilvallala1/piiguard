import json
from fastapi.testclient import TestClient
from piiguard.proxy import create_app

class FakeUpstream:
    def __init__(self):
        self.seen = []
    def chat(self, payload: dict) -> dict:
        self.seen.append(payload)
        user = payload["messages"][-1]["content"]
        return {"id": "x", "object": "chat.completion", "choices": [{"index": 0, "message": {"role": "assistant", "content": f"echo: {user}"}, "finish_reason": "stop"}], "usage": {}}
    def search(self, q: str) -> dict:
        self.seen.append({"q": q})
        return {"hits": [{"title": f"result for {q}"}]}

def test_chat_proxy_redacts_outbound_and_restores_inbound():
    up = FakeUpstream()
    client = TestClient(create_app(upstream=up, token="t"))
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"},
                    json={"model": "m", "messages": [{"role": "user", "content": "Look up SSN 912-34-5678 please"}]})
    assert r.status_code == 200
    assert "912-34-5678" not in json.dumps(up.seen[0])          # never left the host
    assert "[PII_SSN_1]" in up.seen[0]["messages"][-1]["content"]
    assert r.json()["choices"][0]["message"]["content"] == "echo: Look up SSN 912-34-5678 please"  # restored for the agent

def test_search_proxy_redacts_query():
    up = FakeUpstream()
    client = TestClient(create_app(upstream=up, token="t"))
    r = client.get("/you/search", params={"q": "maria.chen@example.com address"}, headers={"Authorization": "Bearer t"})
    assert r.status_code == 200
    assert up.seen[0]["q"] == "[PII_EMAIL_1] address"

def test_rejects_missing_token():
    client = TestClient(create_app(upstream=FakeUpstream(), token="t"))
    assert client.post("/v1/chat/completions", json={"model": "m", "messages": []}).status_code == 401

def test_events_endpoint_reports_redactions():
    up = FakeUpstream()
    client = TestClient(create_app(upstream=up, token="t"))
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"}, json={"model": "m", "messages": [{"role": "user", "content": "ssn 912-34-5678"}]})
    ev = client.get("/events", headers={"Authorization": "Bearer t"}).json()
    assert ev[-1]["redactions"] == 1 and ev[-1]["types"] == ["ssn"]


def test_upstream_failure_returns_502_json_not_500():
    class Broken:
        def chat(self, payload):
            raise ConnectionError("no route to crusoe")
        def search(self, q):
            raise ConnectionError("no route to you.com")
    client = TestClient(create_app(upstream=Broken(), token="t"), raise_server_exceptions=False)
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"}, json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 502
    assert r.json()["error"] == "upstream failure: ConnectionError" and "no route" not in r.text
    r2 = client.get("/you/search", params={"q": "x"}, headers={"Authorization": "Bearer t"})
    assert r2.status_code == 502


def test_tool_call_arguments_and_tool_results_are_redacted():
    up = FakeUpstream()
    client = TestClient(create_app(upstream=up, token="t"))
    msgs = [
        {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "crm", "arguments": "{\"ssn\": \"912-34-5678\"}"}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "record email d.okafor@example.com"},
        {"role": "user", "content": [{"type": "text", "text": "card 4111 1111 1111 1111"}, {"type": "input_text", "text": "phone 555-010-1234"}]},
    ]
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"}, json={"model": "m", "messages": msgs})
    sent = json.dumps(up.seen[0])
    for v in ("912-34-5678", "d.okafor@example.com", "4111 1111 1111 1111", "555-010-1234"):
        assert v not in sent, v


def test_tokens_are_unique_across_messages_and_restore_is_correct():
    class Echo(FakeUpstream):
        def chat(self, payload):
            self.seen.append(payload)
            both = payload["messages"][0]["content"] + " | " + payload["messages"][1]["content"]
            return {"choices": [{"index": 0, "message": {"role": "assistant", "content": both}}]}
    up = Echo()
    client = TestClient(create_app(upstream=up, token="t"))
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"},
                    json={"model": "m", "messages": [{"role": "user", "content": "A 912-34-5678"}, {"role": "user", "content": "B 923-45-6789"}]})
    sent = [m["content"] for m in up.seen[0]["messages"]]
    assert sent == ["A [PII_SSN_1]", "B [PII_SSN_2]"]
    assert r.json()["choices"][0]["message"]["content"] == "A 912-34-5678 | B 923-45-6789"


def test_protocol_key_skip_cannot_be_abused_to_smuggle_pii():
    up = FakeUpstream()
    client = TestClient(create_app(upstream=up, token="t"))
    msgs = [{"role": "user", "content": "hi", "metadata": {"id": "912-34-5678"}, "type": ["923-45-6789"], "tool_call_id": "call 934-56-7890"}]
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"}, json={"model": "m", "messages": msgs})
    sent = json.dumps(up.seen[0])
    for v in ("912-34-5678", "923-45-6789", "934-56-7890"):
        assert v not in sent, v
    assert up.seen[0]["messages"][0]["role"] == "user" and up.seen[0]["model"] == "m"


def test_ids_must_start_with_a_letter_and_roles_must_be_known():
    up = FakeUpstream()
    inspected = []
    def classifier(text, prompt):           # stands in for the LLM: records what gets inspected, flags digit blobs
        inspected.append(text)
        return [{"text": text, "type": "other"}] if text.isdigit() else []
    client = TestClient(create_app(upstream=up, token="t", classifier=classifier))
    msgs = [{"role": "user", "content": "hi", "tool_calls": [{"id": "call_ok1234", "type": "function", "function": {"name": "f", "arguments": "{}"}}, {"id": "393132333435363738", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
            {"role": "nine one two three four", "content": "x"}]
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"}, json={"model": "m", "messages": msgs})
    sent = up.seen[0]
    assert sent["messages"][0]["tool_calls"][0]["id"] == "call_ok1234" and "call_ok1234" not in inspected   # trusted, never inspected
    assert sent["messages"][0]["tool_calls"][1]["id"] == "[PII_OTHER_1]"                            # digits-only id was inspected and caught
    assert "nine one two three four" in inspected                                                      # unknown role is inspected


def test_model_allowlist_and_provider_id_formats():
    up = FakeUpstream()
    inspected = []
    def classifier(text, prompt):
        inspected.append(text); return []
    client = TestClient(create_app(upstream=up, token="t", classifier=classifier, model_allowlist=["good-model"]))
    msgs = [{"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_Ab12cd34", "type": "function", "function": {"name": "f", "arguments": "{}"}},
        {"id": "a912345678", "type": "function", "function": {"name": "f", "arguments": "{}"}}]}]
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"}, json={"model": "good-model", "messages": msgs})
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"}, json={"model": "other-9123456789", "messages": []})
    assert "good-model" not in inspected and "call_Ab12cd34" not in inspected     # allowlisted, untouched
    assert "a912345678" in inspected and "other-9123456789" in inspected           # shape alone is not trust


def test_events_are_written_to_the_configured_path_only(tmp_path, monkeypatch):
    target = tmp_path / "ev.jsonl"
    monkeypatch.setenv("PIIGUARD_EVENTS_PATH", str(target))
    client = TestClient(create_app(upstream=FakeUpstream(), token="t"))
    client.post("/v1/chat/completions", headers={"Authorization": "Bearer t"}, json={"model": "m", "messages": [{"role": "user", "content": "ssn 912-34-5678"}]})
    assert target.exists() and "PII_SSN_1" in target.read_text()
