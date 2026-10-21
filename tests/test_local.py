"""Local base detectors: same Classifier contract as the remote LLM, no network, no model weights in CI."""
import pytest

from piiguard.cli import _classifier
from piiguard.pii.guard import Guard
from piiguard.pii.local import GlinerDetector, PresidioDetector, Stacked, make_detector

RULES = """version: 1
rules:
  - name: ssn
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
"""


class _R:  # minimal presidio RecognizerResult
    def __init__(self, entity_type, start, end):
        self.entity_type, self.start, self.end = entity_type, start, end


class FakeAnalyzer:
    def __init__(self):
        self.calls = []

    def analyze(self, text, language, entities, score_threshold):
        self.calls.append(entities)
        i = text.find("Maria Chen")
        return [_R("PERSON", i, i + len("Maria Chen"))] if i >= 0 else []


def test_presidio_detector_returns_spans_and_scopes_entities():
    fa = FakeAnalyzer()
    d = PresidioDetector(analyzer=fa)
    assert d("call Maria Chen today") == [{"text": "Maria Chen", "type": "person"}]
    assert "DATE_TIME" not in fa.calls[0] and "PERSON" in fa.calls[0]


def test_local_detector_fills_what_rules_miss_and_rules_still_run():
    g = Guard.from_texts(RULES, classifier=PresidioDetector(analyzer=FakeAnalyzer()))
    red = g.redact("Maria Chen, ssn 912-34-5678")
    assert "Maria Chen" not in red.text and "912-34-5678" not in red.text
    assert sorted(red.mapping.values()) == ["912-34-5678", "Maria Chen"]


def test_gliner_detector_windows_long_text_with_correct_offsets():
    text = ("x" * 1500) + " Maria Chen " + ("y" * 50)
    def predict(chunk, labels, threshold):
        i = chunk.find("Maria Chen")
        return [{"start": i, "end": i + 10, "text": "Maria Chen", "label": "person"}] if i >= 0 else []
    d = GlinerDetector(predictor=predict, window_chars=1200, overlap_chars=200)
    assert d(text) == [{"text": "Maria Chen", "type": "person"}]  # found once despite overlapping windows


def test_gliner_type_labels_are_normalized():
    d = GlinerDetector(predictor=lambda c, l, t: [{"start": 0, "end": 4, "label": "Street Address<script>"}])
    assert d("1 Main St")[0]["type"] == "street_address_script"


def test_stacked_unions_detectors_and_exposes_router_info():
    class Remote:
        last = {"route": "small", "ms": 3, "score": 1, "signals": {}}
        def __call__(self, text, prompt, regex_findings=None):
            return [{"text": "Springfield", "type": "city"}]
    s = Stacked(PresidioDetector(analyzer=FakeAnalyzer()), Remote())
    assert {x["text"] for x in s("Maria Chen in Springfield", "")} == {"Maria Chen", "Springfield"}
    assert s.last["route"] == "small"


def test_factory_and_cli_wiring_need_no_network():
    assert make_detector("none") is None
    assert _classifier(False) is None
    assert isinstance(_classifier(False, "presidio"), PresidioDetector)
    assert isinstance(_classifier(False, "gliner"), GlinerDetector)
    assert "api_key" not in make_detector("gliner").labels and "api_key" in make_detector("gliner-broad").labels
    with pytest.raises(ValueError):
        make_detector("bogus")
