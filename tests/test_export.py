"""Exported rules must behave exactly like piiguard's own rules inside Presidio and NeMo Guardrails."""
import asyncio
from pathlib import Path

import pytest
import yaml

from piiguard.eval.datasets import load_jsonl
from piiguard.eval.harness import CLEAN_SAMPLES
from piiguard.export import entity_name, guardrails_config, presidio_dicts, presidio_yaml
from piiguard.pii.rules import RuleSet, load_rules
from piiguard.redteam.domains import DOMAINS, domain_guard
from piiguard.pii.guard import Guard

ROOT = Path(__file__).resolve().parents[1]
RULES = load_rules(ROOT / "guard" / "rules.yaml")


def _corpus() -> list[str]:
    texts = list(CLEAN_SAMPLES)
    for d in ("attacks", "attacks-insurance"):
        for split in ("train", "val", "heldout"):
            texts += [a["text"] for a in load_jsonl(ROOT / "data" / d / f"{split}.jsonl")]
    return texts


def test_entity_names_are_presidio_safe():
    assert entity_name("phone-us spaced") == "PIIGUARD_PHONE_US_SPACED"
    assert entity_name("???") == "PIIGUARD_RULE"


def test_validated_rules_are_skipped_by_default_and_listed():
    recs, skipped = presidio_dicts(RULES)
    names = {r["name"] for r in recs}
    validated = {r.name for r in RULES.rules if r.validator}
    assert validated and set(skipped) == validated and not names & {f"piiguard_{v}" for v in validated}
    assert "Skipped" in presidio_yaml(RULES)
    recs_all, skipped_all = presidio_dicts(RULES, include_validated=True)
    assert len(recs_all) == len(RULES.rules) and skipped_all == []


def test_yaml_round_trips_through_presidio_registry(tmp_path):
    pytest.importorskip("presidio_analyzer")
    from presidio_analyzer import RecognizerRegistry
    p = tmp_path / "recognizers.yaml"
    p.write_text(presidio_yaml(RULES))
    reg = RecognizerRegistry()
    reg.add_recognizers_from_yaml(p)
    loaded = {r.name for r in reg.recognizers}
    assert {r["name"] for r in presidio_dicts(RULES)[0]} <= loaded


@pytest.mark.parametrize("domain", [None, "insurance"])
def test_exported_recognizers_match_exactly_what_piiguard_matches(domain):
    """Parity: for every exported rule, Presidio's spans equal piiguard's own regex spans on the whole corpus."""
    pytest.importorskip("presidio_analyzer")
    from presidio_analyzer import PatternRecognizer
    rules = domain_guard(Guard(RULES), domain).rules if domain else RULES
    by_name = {r.name: r for r in rules.rules}
    recs, _ = presidio_dicts(rules)
    corpus = _corpus()
    checked = 0
    for d in recs:
        rec = PatternRecognizer.from_dict(d)
        rule = by_name[d["patterns"][0]["name"]]
        for text in corpus:
            ours = {(m.start(), m.end()) for m in rule.regex.finditer(text) if m.group(0)}
            theirs = {(x.start, x.end) for x in rec.analyze(text, [d["supported_entity"]])}
            assert theirs == ours, f"{rule.name} differs on {text[:80]!r}"
            checked += bool(ours)
    assert checked > 0


def test_python_recognizers_keep_validators():
    pytest.importorskip("presidio_analyzer")
    from piiguard.export import presidio_recognizers
    rs = RuleSet.from_yaml_text("version: 1\nrules:\n  - name: credit_card\n    pattern: '\\b(?:\\d[ -]?){12,15}\\d\\b'\n    validator: luhn\n")
    (rec,) = presidio_recognizers(rs)
    ent = rec.supported_entities[0]
    assert [x.score for x in rec.analyze("card 4111 1111 1111 1111", [ent])] == [1.0]   # passes Luhn
    assert rec.analyze("order 1234 5678 9012 3456", [ent]) == []                        # fails Luhn, dropped


def test_guardrails_block_is_valid_yaml_with_flows():
    doc = yaml.safe_load(guardrails_config(RULES, extra_entities=["PERSON"]))
    sdd = doc["rails"]["config"]["sensitive_data_detection"]
    assert "PERSON" in sdd["input"]["entities"] and sdd["recognizers"]
    assert doc["rails"]["input"]["flows"] == ["mask sensitive data on input"]


def test_guardrails_masks_an_insurance_badge_end_to_end():
    """Real NeMo Guardrails mask action with the exported config: the badge Presidio alone misses is masked."""
    pytest.importorskip("nemoguardrails")
    pytest.importorskip("presidio_analyzer")
    spacy = pytest.importorskip("spacy")
    if not spacy.util.is_package("en_core_web_lg"):
        pytest.skip("en_core_web_lg not installed")
    from nemoguardrails import RailsConfig
    from nemoguardrails.library.sensitive_data_detection.actions import mask_sensitive_data
    rules = domain_guard(Guard(RULES), "insurance").rules
    cfg = RailsConfig.from_content(yaml_content=guardrails_config(rules, extra_entities=["PERSON"]))
    prompt = DOMAINS["insurance"]["preset"]["prompt"]
    out = asyncio.run(mask_sensitive_data(source="input", text=prompt, config=cfg))
    masked = out.metadata["masked_text"]
    for value in ("ADJ-48213-TX", "CLM-2026-0048213", "POL 88-4421-7730", "555-010-1234", "Maria Chen"):
        assert value not in masked, (value, masked)
