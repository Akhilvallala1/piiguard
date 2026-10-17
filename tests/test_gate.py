from piiguard.coach.gate import decide

def test_accepts_when_leak_drops_and_fp_holds():
    d = decide(before={"leak_rate": 0.60, "fp_rate": 0.05}, after={"leak_rate": 0.40, "fp_rate": 0.06}, min_leak_delta=0.05, max_fp_increase=0.05)
    assert d.accepted and "leak" in d.reason

def test_rejects_when_leak_does_not_drop_enough():
    d = decide(before={"leak_rate": 0.60, "fp_rate": 0.05}, after={"leak_rate": 0.58, "fp_rate": 0.05}, min_leak_delta=0.05, max_fp_increase=0.05)
    assert not d.accepted

def test_rejects_when_false_positives_blow_up_even_if_leak_drops():
    d = decide(before={"leak_rate": 0.60, "fp_rate": 0.05}, after={"leak_rate": 0.10, "fp_rate": 0.40}, min_leak_delta=0.05, max_fp_increase=0.05)
    assert not d.accepted and "false positive" in d.reason


def test_exact_threshold_counts_despite_floating_point():
    d = decide(before={"leak_rate": 0.60, "fp_rate": 0.0}, after={"leak_rate": 0.55, "fp_rate": 0.0}, min_leak_delta=0.05, max_fp_increase=0.05)
    assert d.accepted, d.reason
