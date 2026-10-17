import subprocess
from pathlib import Path
from piiguard.coach.gate import GuardRepo

def _init_repo(tmp_path: Path) -> Path:
    (tmp_path / "guard").mkdir()
    (tmp_path / "guard" / "rules.yaml").write_text("version: 0\nrules: []\n")
    (tmp_path / "guard" / "prompt.md").write_text("v0\n")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"], cwd=tmp_path, check=True)
    return tmp_path

def test_stage_then_revert_restores_files(tmp_path):
    repo = GuardRepo(_init_repo(tmp_path))
    repo.stage("version: 1\nrules: []\n", "v1\n")
    assert (tmp_path / "guard" / "prompt.md").read_text() == "v1\n"
    repo.revert()
    assert (tmp_path / "guard" / "prompt.md").read_text() == "v0\n"

def test_stage_then_commit_creates_tag(tmp_path):
    repo = GuardRepo(_init_repo(tmp_path))
    repo.stage("version: 1\nrules: []\n", "v1\n")
    sha = repo.commit("gen-1", "coach: added base64 rule")
    tags = subprocess.run(["git", "tag"], cwd=tmp_path, capture_output=True, text=True).stdout.split()
    assert "gen-1" in tags and len(sha) >= 7
    assert (tmp_path / "guard" / "prompt.md").read_text() == "v1\n"


def test_files_at_tag_returns_committed_guard_files(tmp_path):
    repo = GuardRepo(_init_repo(tmp_path))
    subprocess.run(["git", "tag", "gen-0"], cwd=tmp_path, check=True)
    repo.stage("version: 1\nrules: []\n", "v1\n")
    repo.commit("gen-1", "gen 1")
    rules, prompt = repo.files_at("gen-0")
    assert rules == "version: 0\nrules: []\n" and prompt == "v0\n"
