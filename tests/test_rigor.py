"""Phase 3 evaluation pieces: statistics, partial-leak scoring, fresh-value sets, clean corpus, statistical gate."""
from pathlib import Path

import pytest

from piiguard.coach.gate import decide_paired
from piiguard.eval.clean_corpus import generate_clean
from piiguard.eval.datasets import load_jsonl
from piiguard.eval.scoring import leak_kind, score_attacks
from piiguard.eval.stats import fmt_rate, mcnemar, paired_counts, wilson
from piiguard.pii.rules import luhn_ok
from piiguard.redteam.fresh import FRESH_CARRIERS, generate_fresh
from piiguard.redteam.generator import CARRIERS, SEED_PEOPLE

ROOT = Path(__file__).resolve().parents[1]


# ---- statistics
def test_wilson_matches_known_values_and_handles_edges():
    lo, hi = wilson(5, 30)                       # textbook: 0.0734, 0.3365
    assert abs(lo - 0.0734) < 1e-3 and abs(hi - 0.3365) < 1e-3
    lo0, hi0 = wilson(0, 30)
    assert lo0 == 0.0 and 0.11 < hi0 < 0.12      # 0/30 is not "0% for sure"
    assert wilson(30, 30)[1] == 1.0
    assert fmt_rate(5, 30).startswith("16.7% [")


def test_mcnemar_exact_values():
    assert mcnemar(0, 0) == 1.0
    assert abs(mcnemar(5, 0) - 1 / 32) < 1e-12   # 5 fixed, 0 broken
    assert abs(mcnemar(2, 0) - 0.25) < 1e-12     # what a 5-point drop on n=30 can look like: not significant
    assert mcnemar(3, 3) > 0.5


def test_paired_counts():
    assert paired_counts([True, True, False, False], [False, True, True, False]) == (1, 1)
    with pytest.raises(ValueError):
        paired_counts([True], [])


# ---- partial-leak scoring
def test_leak_kinds():
    assert leak_kind("ssn 912-34-5678", ["912-34-5678"], "912-34-5678") == "exact"
    assert leak_kind("ssn 912 34 5678", ["OTk="], "912-34-5678") == "value"         # separators changed
    assert leak_kind("ssn [PII_1] 5678", ["912-34-5678"], "912-34-5678") == "partial"  # last 4 survived
    assert leak_kind("ssn [PII_1] ok", ["912-34-5678"], "912-34-5678") == "none"
    assert leak_kind("order 456789012345678 shipped", ["x"], "912-34-5678") == "none"  # tail inside longer run
    assert leak_kind("born [PII_1]", ["x"], "03/14/1988") == "none"


def test_score_attacks_reports_any_leak_rate():
    s = score_attacks([{"id": "a", "leaked": True, "leak_kind": "exact"}, {"id": "b", "leaked": False, "leak_kind": "partial"},
                       {"id": "c", "leaked": False, "leak_kind": "none"}])
    assert s["leaks"] == 1 and s["any_leaks"] == 2 and s["leak_kinds"] == {"exact": 1, "partial": 1, "none": 1}


# ---- fresh-value evaluation set
def test_fresh_set_has_no_value_or_carrier_overlap_with_training():
    seen = {v for p in SEED_PEOPLE for v in p.values()}
    for split in ("train", "val", "heldout"):
        seen |= {a["plain_value"] for a in load_jsonl(ROOT / "data" / "attacks" / f"{split}.jsonl")}
    rows = generate_fresh(300, seed=11, exclude_values=seen)
    assert len(rows) == 300
    assert not any(r["plain_value"] in seen for r in rows)
    assert not set(FRESH_CARRIERS) & set(CARRIERS)
    assert all(r["surface_forms"][0] in r["text"] for r in rows)
    assert all(luhn_ok(r["plain_value"]) for r in rows if r["pii_type"] == "credit_card")
    assert all(r["plain_value"].split("-")[0] >= "900" for r in rows if r["pii_type"] == "ssn")


def test_fresh_set_is_deterministic():
    assert generate_fresh(50, seed=3) == generate_fresh(50, seed=3)


def test_committed_fresh_heldout_matches_the_generator():
    path = ROOT / "data" / "attacks-fresh" / "heldout.jsonl"
    rows = load_jsonl(path)
    assert len(rows) == 500


# ---- clean corpus
def test_clean_corpus_is_large_unique_and_deterministic():
    c = generate_clean()
    assert len(c) >= 1000 and len(set(c)) == len(c)
    assert generate_clean() == c


# ---- statistical gate
def test_stat_gate_rejects_a_noise_sized_improvement():
    before = [True] * 10 + [False] * 20
    after = [False] * 2 + [True] * 8 + [False] * 20        # fixed 2, broke 0: 6.7 points, p=0.25
    d = decide_paired(before, after, [False] * 25, [False] * 25)
    assert not d.accepted and "not significant" in d.reason


def test_stat_gate_accepts_a_real_improvement():
    before = [True] * 10 + [False] * 20
    after = [False] * 6 + [True] * 4 + [False] * 20        # fixed 6, broke 0: p=0.0156
    assert decide_paired(before, after, [False] * 25, [False] * 25).accepted


def test_stat_gate_rejects_new_false_positives():
    before = [True] * 10 + [False] * 20
    after = [False] * 10 + [False] * 20
    d = decide_paired(before, after, [False] * 25, [True] + [False] * 24)
    assert not d.accepted and "false positive" in d.reason
