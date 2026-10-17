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
