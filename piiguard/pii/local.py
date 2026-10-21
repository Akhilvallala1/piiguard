"""Local base detectors: find semantic PII (names, places, organizations) on this machine, so raw text never has to
leave the host just to be classified.

Each detector has the same Classifier signature the Guard already uses, (text, prompt, regex_findings=None) -> spans,
where a span is {"text": str, "type": str}. The learned regex rules still run first; a local detector adds what rules
cannot shape-match. A remote LLM classifier is optional and can be stacked behind it with `Stacked`.

Both backends are optional dependencies:
  pip install "piiguard[presidio]"   # Microsoft Presidio + spaCy (python -m spacy download en_core_web_lg)
  pip install "piiguard[gliner]"     # GLiNER with nvidia/gliner-PII weights (downloaded on first use)
"""
from __future__ import annotations

import re
import threading
from typing import Callable, Iterable, Optional

_TYPE_OK = re.compile(r"[^a-z0-9_]+")

# Presidio entities that are mostly noise on agent traffic (timestamps, links, nationalities). The learned rules and
# the URL-aware proxy handle the structured ones that matter; leaving these out keeps false positives down.
PRESIDIO_DEFAULT_ENTITIES = [
    "PERSON", "LOCATION", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS",
    "US_BANK_NUMBER", "US_DRIVER_LICENSE", "US_PASSPORT", "US_ITIN", "MEDICAL_LICENSE", "CRYPTO", "MAC_ADDRESS",
]

# Labels for GLiNER, a zero-shot model: plain-language names are what it was trained to match.
# "precise" (default): semantic PII plus contact details; structured ids are left to the learned rules, because
# GLiNER labels timestamps as dates of birth, SKUs as customer ids and commit hashes as passwords.
# "broad": every label; catches more obfuscated identifiers at a real false-positive cost. See README results.
GLINER_PRECISE_LABELS = ["person", "first_name", "last_name", "street_address", "city", "company_name", "email", "phone_number"]
GLINER_BROAD_LABELS = GLINER_PRECISE_LABELS + [
    "ssn", "date_of_birth", "medical_record_number", "account_number", "credit_debit_card", "customer_id", "employee_id",
    "license_plate", "api_key", "password", "ipv4",
]
GLINER_DEFAULT_LABELS = GLINER_PRECISE_LABELS


def _norm_type(t: str) -> str:
    t = _TYPE_OK.sub("_", str(t).strip().lower()).strip("_")[:32]
    return t or "other"


class PresidioDetector:
    """Microsoft Presidio's analyzer as a local span detector."""

    name = "presidio"

    def __init__(self, entities: Optional[Iterable[str]] = None, score_threshold: float = 0.5,
                 spacy_model: str = "en_core_web_lg", analyzer=None):
        self.entities = list(entities) if entities is not None else list(PRESIDIO_DEFAULT_ENTITIES)
        self.score_threshold = score_threshold
        self._spacy_model = spacy_model
        self._analyzer = analyzer
        self._lock = threading.Lock()

    def _engine(self):
        with self._lock:
            if self._analyzer is None:
                from presidio_analyzer import AnalyzerEngine
                from presidio_analyzer.nlp_engine import NlpEngineProvider
                cfg = {"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": self._spacy_model}]}
                self._analyzer = AnalyzerEngine(nlp_engine=NlpEngineProvider(nlp_configuration=cfg).create_engine())
            return self._analyzer

    def __call__(self, text: str, prompt: str = "", regex_findings=None) -> list[dict]:
        if not text.strip():
            return []
        results = self._engine().analyze(text=text, language="en", entities=self.entities, score_threshold=self.score_threshold)
        return [{"text": text[r.start:r.end], "type": _norm_type(r.entity_type)} for r in results if r.end > r.start]


class GlinerDetector:
    """GLiNER (default weights: nvidia/gliner-PII) as a local span detector. Long texts are scanned in overlapping
    windows because the model has a fixed context."""

    name = "gliner"

    def __init__(self, model: str = "nvidia/gliner-PII", labels: Optional[Iterable[str]] = None, threshold: float = 0.7,
                 window_chars: int = 1200, overlap_chars: int = 200, predictor: Optional[Callable] = None):
        self.model_name = model
        self.labels = list(labels) if labels is not None else list(GLINER_DEFAULT_LABELS)
        self.threshold = threshold
        self.window_chars = window_chars
        self.overlap_chars = overlap_chars
        self._predict = predictor  # (text, labels, threshold) -> [{"start","end","text","label"}]
        self._lock = threading.Lock()

    def _predictor(self) -> Callable:
        with self._lock:
            if self._predict is None:
                from gliner import GLiNER
                model = GLiNER.from_pretrained(self.model_name)
                self._predict = lambda text, labels, threshold: model.predict_entities(text, labels, threshold=threshold)
            return self._predict

    def _windows(self, text: str):
        step = max(1, self.window_chars - self.overlap_chars)
        start = 0
        while True:
            yield start, text[start:start + self.window_chars]
            if start + self.window_chars >= len(text):
                return
            start += step

    def __call__(self, text: str, prompt: str = "", regex_findings=None) -> list[dict]:
        if not text.strip():
            return []
        predict = self._predictor()
        seen: set[tuple[int, int]] = set()
        spans: list[dict] = []
        for offset, chunk in self._windows(text):
            for e in predict(chunk, self.labels, self.threshold) or []:
                s, t = offset + int(e["start"]), offset + int(e["end"])
                if t <= s or (s, t) in seen:
                    continue
                seen.add((s, t))
                spans.append({"text": text[s:t], "type": _norm_type(e.get("label", "other"))})
        return spans


class Stacked:
    """Run several detectors and union their spans. Typical: a local detector, then an optional remote LLM.
    Exposes `.last` from the last detector that has one (the router), so the proxy's route display keeps working."""

    def __init__(self, *detectors):
        self.detectors = [d for d in detectors if d is not None]

    @property
    def last(self):
        for d in reversed(self.detectors):
            if hasattr(d, "last"):
                return d.last
        return {"route": "local", "ms": 0, "score": 0, "signals": {}}

    def __call__(self, text: str, prompt: str = "", regex_findings=None) -> list[dict]:
        out: list[dict] = []
        for d in self.detectors:
            try:
                out.extend(d(text, prompt, regex_findings=regex_findings))
            except TypeError:
                out.extend(d(text, prompt))
        return out


def make_detector(kind: Optional[str], **kw):
    """'none' | 'presidio' | 'gliner' | 'gliner-broad' -> detector or None."""
    kind = (kind or "none").lower()
    if kind == "none":
        return None
    if kind == "presidio":
        return PresidioDetector(**kw)
    if kind == "gliner":
        return GlinerDetector(**kw)
    if kind == "gliner-broad":
        return GlinerDetector(labels=GLINER_BROAD_LABELS, **kw)
    raise ValueError(f"unknown detector {kind!r}; choose one of {', '.join(DETECTORS)}")


DETECTORS = ["none", "presidio", "gliner", "gliner-broad"]
