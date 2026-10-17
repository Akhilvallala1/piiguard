import json
from fastapi.testclient import TestClient
from piiguard.redteam.domains import DOMAINS, domain_guard
from piiguard.pii.guard import Guard
from piiguard.proxy import create_app


def test_every_domain_pack_is_internally_consistent():
    for name, d in DOMAINS.items():
        assert {"people", "pii_types", "labels", "prompt_addendum", "seed_rules", "preset"} <= set(d), name
        for v in d["preset"]["expected"]:
            assert v in d["preset"]["prompt"], (name, v)
        g = domain_guard(Guard.from_dir("guard"), name)           # seed rules compile and attach
        assert d["prompt_addendum"] in g.prompt


def test_seed_rules_catch_the_domain_identifiers_in_each_preset():
    for name, d in DOMAINS.items():
        g = domain_guard(Guard.from_dir("guard"), name)
        red = g.redact(d["preset"]["prompt"])
        for v in d["preset"]["expected"]:
            if d["preset"].get("rules_catch", {}).get(v, True):
                assert v not in red.text, (name, v)


def test_demo_run_marks_misses_against_domain_ground_truth():
    class Up:
        def chat(self, payload): return {"choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}]}
        def search(self, q): return {}
    client = TestClient(create_app(upstream=Up(), token="t"))
    doms = client.get("/demo/domains", headers={"Authorization": "Bearer t"}).json()
    assert {"insurance", "healthcare", "finance", "legal"} <= set(doms)
    ins = doms["insurance"]
    r = client.post("/demo/run", headers={"Authorization": "Bearer t"}, json={"prompt": ins["preset"]["prompt"], "domain": "insurance"}).json()
    assert r["expected"] == ins["preset"]["expected"]
    rules_catch = ins["preset"].get("rules_catch", {})
    assert all(not rules_catch.get(v, True) for v in r["rules_only"]["missed"])   # only names are left for the classifier
    assert "ADJ-48213-TX" in r["direct"]["text"]


def test_a_value_counts_as_leaked_if_its_core_survives_without_its_label():
    from piiguard.proxy import _missed_values
    truth = ["MRN 00482137", "NPI 1932847561", "Grace Kim", "routing 021000021"]
    text = "Patient <PERSON>, <ORGANIZATION> 00482137, <UK_NHS> for follow-up, routing <PHONE_NUMBER>"
    assert _missed_values(text, truth) == ["MRN 00482137"]          # the record number is still readable; NPI and routing are gone
