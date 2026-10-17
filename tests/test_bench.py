import pytest
from piiguard.bench import run_bench

ATTACKS = [
    {"id": "a", "technique": "plain", "pii_type": "ssn", "text": "ssn 912-34-5678", "surface_forms": ["912-34-5678"]},
    {"id": "b", "technique": "base64", "pii_type": "ssn", "text": "ssn OTEyLTM0LTU2Nzg=", "surface_forms": ["OTEyLTM0LTU2Nzg="]},
]
CLEAN = ["ship it on Friday", "port 8080 is open"]

def test_bench_scores_each_system_on_same_data():
    systems = {
        "nothing": lambda t: t,
        "redact_all": lambda t: "[X]",
        "ssn_only": lambda t: t.replace("912-34-5678", "[SSN]"),
    }
    rows = run_bench(systems, ATTACKS, CLEAN)
    by = {r["system"]: r for r in rows}
    assert by["nothing"]["leak_rate"] == 1.0 and by["nothing"]["fp_rate"] == 0.0
    assert by["redact_all"]["leak_rate"] == 0.0 and by["redact_all"]["fp_rate"] == 1.0
    assert by["ssn_only"]["leak_rate"] == 0.5 and by["ssn_only"]["fp_rate"] == 0.0
    assert by["ssn_only"]["by_technique"]["base64"] == 1.0

def test_presidio_adapter_redacts_plain_ssn_and_email():
    pytest.importorskip("presidio_analyzer")
    from piiguard.bench import presidio_redactor
    red = presidio_redactor()
    out = red("Contact maria.chen@example.com, SSN 912-34-5678.")
    assert "maria.chen@example.com" not in out and "912-34-5678" not in out


def test_presidio_scoped_adapter_ignores_dates_and_places():
    pytest.importorskip("presidio_analyzer")
    from piiguard.bench import presidio_redactor
    red = presidio_redactor(entities=["US_SSN", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"])
    assert red("Meeting on 2026-10-17 at the Ferry Building with Maria Chen.") == "Meeting on 2026-10-17 at the Ferry Building with Maria Chen."
    assert "912-34-5678" not in red("SSN 912-34-5678")
