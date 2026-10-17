import subprocess, sys, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable

def test_redact_command_prints_redacted_text():
    out = subprocess.run([PY, "-m", "piiguard.cli", "redact", "call 555-010-1234 now"], capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    assert "[PII_PHONE_US_1]" in out.stdout

def test_gen_attacks_writes_three_splits(tmp_path):
    out = subprocess.run([PY, "-m", "piiguard.cli", "gen-attacks", "--n", "20", "--seed", "5", "--out", str(tmp_path)], capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    assert {p.name for p in tmp_path.iterdir()} == {"train.jsonl", "val.jsonl", "heldout.jsonl"}

def test_eval_command_reports_scores_as_json(tmp_path):
    subprocess.run([PY, "-m", "piiguard.cli", "gen-attacks", "--n", "20", "--seed", "5", "--out", str(tmp_path)], check=True, cwd=ROOT, capture_output=True)
    out = subprocess.run([PY, "-m", "piiguard.cli", "eval", "--data", str(tmp_path), "--set", "heldout", "--json"], capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0, out.stderr
    s = json.loads(out.stdout)
    assert 0.0 <= s["attacks"]["leak_rate"] <= 1.0 and "fp_rate" in s["clean"]
