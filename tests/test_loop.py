import subprocess
from pathlib import Path
from piiguard.loop import run_generation
from piiguard.coach.retrospective import Proposal
from piiguard.pii.rules import RuleSet

GEN0_RULES = "version: 0\nrules:\n  - name: ssn\n    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'\n"
BETTER_RULES = GEN0_RULES + "  - name: ssn_b64\n    pattern: 'MTIzLTQ1LTY3ODk='\n"

def _repo(tmp_path: Path) -> Path:
    (tmp_path / "guard").mkdir()
    (tmp_path / "guard" / "rules.yaml").write_text(GEN0_RULES)
    (tmp_path / "guard" / "prompt.md").write_text("v0\n")
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"], ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"]):
        subprocess.run(cmd, cwd=tmp_path, check=True)
    return tmp_path

ATTACKS = [
    {"id": "a", "technique": "plain", "pii_type": "ssn", "text": "ssn 123-45-6789", "surface_forms": ["123-45-6789"]},
    {"id": "b", "technique": "base64", "pii_type": "ssn", "text": "ssn MTIzLTQ1LTY3ODk=", "surface_forms": ["MTIzLTQ1LTY3ODk="]},
]
CLEAN = ["hello there", "ship it"]

def _proposal(rules_yaml):
    return Proposal("test", rules_yaml, "v1\n", RuleSet.from_yaml_text(rules_yaml))

def test_helpful_proposal_is_committed_and_tagged(tmp_path):
    root = _repo(tmp_path)
    rec = run_generation(root, gen=1, train=ATTACKS, val=ATTACKS, clean=CLEAN, coach_fn=lambda misses, r, p, s: _proposal(BETTER_RULES))
    assert rec["accepted"] is True
    assert rec["val_before"]["leak_rate"] == 0.5 and rec["val_after"]["leak_rate"] == 0.0
    tags = subprocess.run(["git", "tag"], cwd=root, capture_output=True, text=True).stdout.split()
    assert "gen-1" in tags
    assert "ssn_b64" in (root / "guard" / "rules.yaml").read_text()

def test_useless_proposal_is_reverted_and_logged(tmp_path):
    root = _repo(tmp_path)
    rec = run_generation(root, gen=1, train=ATTACKS, val=ATTACKS, clean=CLEAN, coach_fn=lambda misses, r, p, s: _proposal(GEN0_RULES))
    assert rec["accepted"] is False and "rejected" in rec["reason"]
    assert (root / "guard" / "prompt.md").read_text() == "v0\n"
    assert (root / "runs" / "history.jsonl").exists()

def test_coach_receives_only_the_misses(tmp_path):
    root = _repo(tmp_path)
    seen = {}
    def coach(misses, rules_yaml, prompt_md, scores):
        seen["ids"] = [m["id"] for m in misses]
        return _proposal(BETTER_RULES)
    run_generation(root, gen=1, train=ATTACKS, val=ATTACKS, clean=CLEAN, coach_fn=coach)
    assert seen["ids"] == ["b"]


def test_coach_failure_is_recorded_as_rejected_generation_not_crash(tmp_path):
    root = _repo(tmp_path)
    def broken_coach(misses, r, p, s):
        raise RuntimeError("coach produced garbage three times")
    rec = run_generation(root, gen=1, train=ATTACKS, val=ATTACKS, clean=CLEAN, coach_fn=broken_coach)
    assert rec["accepted"] is False and "coach" in rec["reason"]
    assert (root / "guard" / "prompt.md").read_text() == "v0\n"
    assert (root / "runs" / "history.jsonl").exists()


def test_missing_prompt_in_proposal_keeps_current_prompt(tmp_path):
    root = _repo(tmp_path)
    coach = lambda misses, r, p, s: Proposal("rules only", BETTER_RULES, None, RuleSet.from_yaml_text(BETTER_RULES))
    rec = run_generation(root, gen=1, train=ATTACKS, val=ATTACKS, clean=CLEAN, coach_fn=coach)
    assert rec["accepted"] is True
    assert (root / "guard" / "prompt.md").read_text() == "v0\n"


def test_rejected_record_lists_which_clean_samples_the_candidate_flagged(tmp_path):
    root = _repo(tmp_path)
    greedy = GEN0_RULES + "  - name: anydate\n    pattern: '\\b\\d{4}-\\d{2}-\\d{2}\\b'\n"
    coach = lambda misses, r, p, s: _proposal(greedy)
    rec = run_generation(root, gen=1, train=ATTACKS, val=ATTACKS, clean=["shipped on 2026-10-17", "hello"], coach_fn=coach, max_fp_increase=0.0)
    assert rec["accepted"] is False
    assert rec["fp_examples"] == [{"rule": "anydate", "text": "shipped on 2026-10-17", "value": "2026-10-17"}]
