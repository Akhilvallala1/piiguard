"""Small-LLM span classifier (Nemotron 3.5 Lightning on Crusoe) that catches what regex misses.
Its instructions live in guard/prompt.md, which the coach evolves."""
from __future__ import annotations

import json
import re
import threading
from typing import Callable, Optional

_FENCE = re.compile(r"^```[a-zA-Z]*\s*|\s*```$", re.MULTILINE)
_TYPE_OK = re.compile(r"^[a-z0-9_]{1,32}$")


class LLMClassifier:
    def __init__(self, chat_fn: Optional[Callable] = None, models=None):
        self._chat = chat_fn
        self._models = models
        self._cache: dict[tuple[str, str], list[dict]] = {}
        self._lock = threading.Lock()

    def _call(self, messages: list[dict]) -> str:
        if self._chat is None:
            from ..crusoe import chat, WORKER_MODEL, FALLBACK_MODEL
            return chat(messages, models=self._models or [WORKER_MODEL, FALLBACK_MODEL], json_mode=True, max_tokens=1024, temperature=0.0)
        return self._chat(messages)

    def __call__(self, text: str, prompt: str) -> list[dict]:
        key = (prompt, text)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        messages = [{"role": "system", "content": prompt}, {"role": "user", "content": "TEXT:\n" + text}]
        try:
            raw = self._call(messages)
            spans = _parse_spans(raw)
        except Exception:  # noqa: BLE001 - a classifier failure must never crash the guard
            spans = []
        spans = [s for s in spans if s["text"] and s["text"] in text]
        with self._lock:
            self._cache[key] = spans
        return spans


def _parse_spans(raw: str) -> list[dict]:
    cleaned = _FENCE.sub("", raw.strip()).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        return []
    try:
        data = json.loads(cleaned[start:end + 1])
    except json.JSONDecodeError:
        return []
    out = []
    for s in data.get("spans", []) or []:
        if isinstance(s, dict):
            t = str(s.get("type", "other")).strip().lower().replace(" ", "_").replace("-", "_")
            if not _TYPE_OK.match(t):
                t = "other"  # the model's label is untrusted output; never let it carry markup into logs or pages
            out.append({"text": str(s.get("text", "")), "type": t})
    return out
