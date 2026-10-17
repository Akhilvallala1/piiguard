from piiguard.report import render_markdown

def test_markdown_has_generation_rows_and_heldout_line():
    history = [
        {"gen": 1, "accepted": True, "rationale": "spaced digits", "reason": "accepted: leak rate down 0.20", "val_before": {"leak_rate": 0.7}, "val_after": {"leak_rate": 0.5}, "fp_before": {"fp_rate": 0.0}, "fp_after": {"fp_rate": 0.0}, "commit": "abc1234"},
        {"gen": 2, "accepted": False, "rationale": "base64 everywhere", "reason": "rejected: false positive rate rose by 1.00", "val_before": {"leak_rate": 0.5}, "val_after": {"leak_rate": 0.1}, "fp_before": {"fp_rate": 0.0}, "fp_after": {"fp_rate": 1.0}, "commit": None},
    ]
    report = {"heldout_before": {"leak_rate": 0.7667, "n": 30}, "heldout_after": {"leak_rate": 0.3, "n": 30}, "fp_before": {"fp_rate": 0.0}, "fp_after": {"fp_rate": 0.0}}
    md = render_markdown(history, report)
    assert "| 1 |" in md and "| 2 |" in md
    assert "76.7%" in md and "30.0%" in md
    assert "spaced digits" in md and "rejected" in md and "abc1234" in md
