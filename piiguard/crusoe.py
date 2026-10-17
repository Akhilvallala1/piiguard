"""Crusoe Managed Inference client (OpenAI-compatible) with retry + model fallback."""
from __future__ import annotations

import os
import time
from typing import Callable, Sequence

from .env import load_dotenv as _load_dotenv

_load_dotenv()
DEFAULT_BASE_URL = "https://api.inference.crusoecloud.com/v1"
WORKER_MODEL = os.environ.get("WORKER_MODEL", "nvidia/Nemotron-3.5-Lightning-30B-A3B")
COACH_MODEL = os.environ.get("COACH_MODEL", "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B")
FALLBACK_MODEL = os.environ.get("FALLBACK_MODEL", "deepseek-ai/Deepseek-V4-Flash")


def get_client():
    from openai import OpenAI
    from .env import load_dotenv

    load_dotenv()
    key = os.environ.get("CRUSOE_API_KEY")
    if not key:
        raise RuntimeError("CRUSOE_API_KEY is not set (export it in your shell; quote it, keys may contain $)")
    return OpenAI(base_url=os.environ.get("CRUSOE_BASE_URL", DEFAULT_BASE_URL), api_key=key)


def chat_with_fallback(call: Callable, models: Sequence[str], messages: list[dict], retries: int = 3, backoff: float = 1.0, **kw):
    """Try each model in order; retry transient failures (429/503) with exponential backoff."""
    last: Exception | None = None
    for model in models:
        for attempt in range(retries):
            try:
                return call(model, messages, **kw)
            except Exception as e:  # noqa: BLE001 - provider errors are heterogeneous
                last = e
                if attempt + 1 < retries:
                    time.sleep(backoff * (2 ** attempt))
    assert last is not None
    raise last


def chat(messages: list[dict], models: Sequence[str] | None = None, json_mode: bool = False, max_tokens: int = 4096, temperature: float = 0.2) -> str:
    client = get_client()

    def _call(model, msgs, **_):
        kwargs = dict(model=model, messages=msgs, max_tokens=max_tokens, temperature=temperature)
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        resp = client.chat.completions.create(**kwargs)
        content = resp.choices[0].message.content or ""
        if not content.strip():
            raise RuntimeError(f"empty completion from {model}")
        return content

    return chat_with_fallback(_call, models or [WORKER_MODEL, FALLBACK_MODEL], messages)


def list_models() -> list[str]:
    return sorted(m.id for m in get_client().models.list().data)
