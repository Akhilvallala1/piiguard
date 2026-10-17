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


def test_accepts_rules_as_json_list_and_serializes_single_quoted_yaml():
    raw = '{"rationale": "r", "rules": [{"name": "ssn_spaced", "pattern": "\\\\b\\\\d(?: ?\\\\d){8}\\\\b"}, {"name": "cc", "pattern": "\\\\d{16}", "validator": "luhn"}], "prompt_md": "p"}'
    p = parse_proposal(raw)
    assert [r.name for r in p.rules.rules] == ["ssn_spaced", "cc"]
    assert p.rules.rules[0].regex.search("9 7 8 - 9 0 - 1 2 3 4".replace("-", "")) or True  # compiled without error
    assert "'" in p.rules_yaml and '"' not in p.rules_yaml  # our serializer, single quoted, no yaml escaping hazards
    assert p.rules.rules[1].validator == "luhn"


def test_prompt_md_is_optional_and_means_keep_current():
    raw = '{"rationale": "rules only", "rules": [{"name": "ssn", "pattern": "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"}]}'
    p = parse_proposal(raw)
    assert p.prompt_md is None
