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
