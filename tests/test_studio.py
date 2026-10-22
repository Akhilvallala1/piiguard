from fastapi.testclient import TestClient

from piiguard.proxy import create_app
from piiguard.studio import custom_rules, suggest_pattern


class Up:
    base = "http://127.0.0.1:1/v1"
    key = ""

    def __init__(self):
        self.seen = []

    def chat(self, payload):
        self.seen.append(payload)
        return {"choices": [{"message": {"role": "assistant", "content": "ok " + payload["messages"][-1]["content"]}}]}


def _client():
    up = Up()
    return TestClient(create_app(upstream=up, token="t", model_allowlist=["m"])), up


def test_suggest_pattern_keeps_prefix_and_counts_digits():
    p = suggest_pattern("MBR-20231187")
    assert p == r"\bMBR[-‑]\d{8}\b"
    import re
    assert re.search(p, "member MBR-55554444 called")
    assert not re.search(p, "MBR-5555444")


def test_custom_rules_are_bounded_and_named():
    assert custom_rules([{"name": "Member ID!", "pattern": "x"}]) == [{"name": "member_id", "pattern": "x"}]
    for bad in ([{"name": "a"}], [{"pattern": "y" * 500}], [{"pattern": "x"}] * 7, "nope"):
        try:
            custom_rules(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad!r}")


def test_studio_page_embeds_public_record_and_needs_no_token():
    c, _ = _client()
    r = c.get("/studio")
    assert r.status_code == 200 and "The model sees" in r.text
    assert "/*__STUDIO_DATA__*/null" not in r.text           # data was embedded
    d = c.get("/studio/data").json()
    assert {"generations", "rules", "examples", "heldout"} <= set(d)
    assert "key" not in str(d.get("upstream", {})).lower()


def test_redact_applies_page_rules_without_touching_disk():
    c, _ = _client()
    text = "Member MBR-20231187, claim CLM-2026-0048213"
    plain = c.post("/studio/redact", json={"text": text}).json()
    assert "MBR-20231187" in plain["after"]["text"]
    withrule = c.post("/studio/redact", json={"text": text, "rules": [{"name": "member id", "pattern": r"\bMBR-\d{8}\b"}]}).json()
    assert "MBR-20231187" not in withrule["after"]["text"] and "[PII_MEMBER_ID_1]" in withrule["after"]["text"]
    assert "'name': 'member_id'" in withrule["snippet"]
    again = c.post("/studio/redact", json={"text": text}).json()   # the rule lived in that request only
    assert "MBR-20231187" in again["after"]["text"]


def test_unsafe_page_rule_is_rejected_with_a_message():
    c, _ = _client()
    r = c.post("/studio/redact", json={"text": "x", "rules": [{"name": "bad", "pattern": "(a+)+$"}]})
    assert r.status_code == 400 and "unsafe" in r.json()["detail"]


def test_send_needs_the_token_and_only_placeholders_leave():
    c, up = _client()
    body = {"text": "Member MBR-20231187, SSN 912-34-5678", "rules": [{"name": "member id", "pattern": r"\bMBR-\d{8}\b"}]}
    assert c.post("/studio/send", json=body).status_code == 401
    d = c.post("/studio/send", json=body, headers={"Authorization": "Bearer t"}).json()
    sent = str(up.seen[-1])
    assert "912-34-5678" not in sent and "MBR-20231187" not in sent
    assert d["reply"] == "ok Member MBR-20231187, SSN 912-34-5678"


def test_assets_cannot_escape_their_folder():
    c, _ = _client()
    assert c.get("/studio/assets/redacted-cia-document.jpg").status_code == 200
    assert c.get("/studio/assets/..%2F..%2Fproxy.py").status_code == 404
    assert c.get("/studio/assets/credits.json").status_code == 404
