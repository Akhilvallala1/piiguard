import pytest
from piiguard.coach.retrospective import parse_proposal, ProposalError

GOOD = '{"rationale": "add base64 ssn", "rules_yaml": "version: 1\\nrules:\\n  - name: ssn\\n    pattern: \'\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b\'\\n", "prompt_md": "Detect PII."}'

def test_parses_valid_proposal_and_compiles_rules():
    p = parse_proposal(GOOD)
    assert p.rationale == "add base64 ssn"
    assert p.rules.rules[0].name == "ssn"

def test_rejects_invalid_regex():
    bad = '{"rationale": "x", "rules_yaml": "version: 1\\nrules:\\n  - name: ssn\\n    pattern: \'(\'\\n", "prompt_md": "p"}'
    with pytest.raises(ProposalError):
        parse_proposal(bad)

def test_rejects_non_json():
    with pytest.raises(ProposalError):
        parse_proposal("sure! here is yaml: ...")

def test_tolerates_markdown_code_fence_around_json():
    assert parse_proposal("```json\n" + GOOD + "\n```").rationale == "add base64 ssn"
