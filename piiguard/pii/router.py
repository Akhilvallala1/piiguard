"""Complexity routing for the classifier: pay for a model only when the text earns it.

Cheap signals decide between three routes:
  skip  -> the regex rules already explained everything suspicious; no model call (free, ~0 ms)
  small -> residual signals; Nemotron 3.5 Lightning (fast, 3B active parameters)
  large -> many signals or long text; Nemotron 3 Super (slower, stronger)
The router is a plain function so another policy engine (e.g. NVIDIA NeMo Switchyard) can replace it behind the
same Classifier interface."""
from __future__ import annotations

import re
import time
from typing import Callable, Optional

_DIGIT_RUN = re.compile(r"\d[\d \-.]{3,}\d")
_B64 = re.compile(r"\b[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX = re.compile(r"\b[0-9a-fA-F]{12,}\b")
_NUMBER_WORDS = re.compile(r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine)\b", re.I)
_FULLWIDTH = re.compile(r"[０-９％]")
_PCT = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}|(?:％\d{2}){2,}")
_ODD_SEP = re.compile(r"[‑  ]")
_AT = re.compile(r"@")
_ID_LIKE = re.compile(r"\b[A-Z]{2,5}[- ]?\d{3,}(?:[- ][A-Z0-9]{2,})?\b")
_CAP_PAIR = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")
_KEYWORDS = re.compile(r"\b(ssn|social|dob|birth|passport|license|licence|card|account|routing|iban|badge|claim|policy|member|patient|mrn|case)\b", re.I)

SMALL_MAX_SCORE = 4
LARGE_MIN_CHARS = 600
# Fail closed by default: a zero-signal text skips the model only if it is short. Longer prose can carry semantic PII
# with no shape at all (a described person, a condition), so it still gets the small model. Raise with care.
SKIP_MAX_CHARS = 160


def complexity(text: str, regex_findings) -> dict:
    """Score the text AFTER masking what regex already caught; what remains is what a model would have to find."""
    masked = text
    for f in sorted(regex_findings or [], key=lambda f: -f.start):
        masked = masked[: f.start] + " " * (f.end - f.start) + masked[f.end:]
    signals: dict[str, int] = {}
    def add(name, n):
        if n:
            signals[name] = n
    # each signal is capped so one feature alone cannot escalate; escalation needs breadth or length
    add("digit_runs", min(2, len(_DIGIT_RUN.findall(masked))))
    add("base64_like", min(2, len(_B64.findall(masked))))
    add("hex_runs", min(2, len(_HEX.findall(masked))))
    nw = len(_NUMBER_WORDS.findall(masked)); add("number_words", 2 if nw >= 3 else 0)
    add("fullwidth", 1 if _FULLWIDTH.search(masked) else 0)
    add("percent_encoded", 1 if _PCT.search(masked) else 0)
    add("odd_separators", 1 if _ODD_SEP.search(masked) else 0)
    add("at_sign", 1 if _AT.search(masked) else 0)
    add("id_like", min(2, len(_ID_LIKE.findall(masked))))
    add("name_like", min(2, len(_CAP_PAIR.findall(masked))))
    add("keywords", min(2, len(_KEYWORDS.findall(masked))))
    score = sum(signals.values())
    return {"score": score, "signals": signals, "chars": len(text)}


def route(c: dict) -> str:
    if c["score"] == 0 and c["chars"] <= SKIP_MAX_CHARS:
        return "skip"
    if c["score"] > SMALL_MAX_SCORE or c["chars"] > LARGE_MIN_CHARS:
        return "large"
    return "small"


class RoutedClassifier:
    """Classifier (text, prompt[, regex_findings]) -> spans, choosing the route per text and recording it in .last."""

    def __init__(self, small_chat: Optional[Callable] = None, large_chat: Optional[Callable] = None,
                 small_models=None, large_models=None):
        from .classifier import LLMClassifier
        self.small = LLMClassifier(chat_fn=small_chat, models=small_models)
        self.large = LLMClassifier(chat_fn=large_chat, models=large_models)
        self.last: dict = {"route": None, "ms": 0, "score": 0, "signals": {}}
        self.counts = {"skip": 0, "small": 0, "large": 0}

    def __call__(self, text: str, prompt: str, regex_findings=None) -> list[dict]:
        t0 = time.perf_counter()
        c = complexity(text, regex_findings or [])
        r = route(c)
        spans = [] if r == "skip" else (self.small if r == "small" else self.large)(text, prompt)
        self.counts[r] += 1
        self.last = {"route": r, "ms": round((time.perf_counter() - t0) * 1000), "score": c["score"], "signals": c["signals"]}
        return spans
