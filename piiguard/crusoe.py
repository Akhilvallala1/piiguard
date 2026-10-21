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


# ---- spend metering. Prices are USD per 1M tokens (input, output) from Crusoe's public pricing page; unknown models
# are charged at the most expensive listed rate so the estimate errs high. PIIGUARD_BUDGET_USD caps a process: the
# call that would cross it raises BudgetExceeded instead of running.
PRICES = {  # only rates with a public source; everything else is charged at _WORST
    "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B": (0.30, 2.40),
    "openai/gpt-oss-120b": (0.05, 0.20),
    "deepseek-ai/DeepSeek-V4-Pro": (1.74, 3.48),
}
_WORST = (1.74, 3.48)  # highest listed Crusoe serverless rate


class BudgetExceeded(RuntimeError):
    pass


class Meter:
    def __init__(self):
        import threading
        self.lock = threading.Lock()
        self.usd = 0.0
        self.tokens = {}  # model -> [in, out]

    @property
    def budget(self) -> float | None:
        b = os.environ.get("PIIGUARD_BUDGET_USD")
        return float(b) if b else None

    def check(self):
        b = self.budget
        if b is not None and self.usd >= b:
            raise BudgetExceeded(f"spend ${self.usd:.2f} reached PIIGUARD_BUDGET_USD=${b:.2f}")

    def add(self, model: str, prompt: int, completion: int):
        pin, pout = PRICES.get(model, _WORST)
        with self.lock:
            t = self.tokens.setdefault(model, [0, 0])
            t[0] += prompt
            t[1] += completion
            self.usd += prompt / 1e6 * pin + completion / 1e6 * pout

    def summary(self) -> str:
        parts = [f"{m.split('/')[-1]} {i:,} in / {o:,} out" for m, (i, o) in sorted(self.tokens.items())]
        return f"estimated spend ${self.usd:.2f}" + (f" ({'; '.join(parts)})" if parts else "")


METER = Meter()


def chat_with_fallback(call: Callable, models: Sequence[str], messages: list[dict], retries: int = 3, backoff: float = 1.0, **kw):
    """Try each model in order; retry transient failures (429/503) with exponential backoff."""
    last: Exception | None = None
    for model in models:
        for attempt in range(retries):
            try:
                METER.check()
                return call(model, messages, **kw)
            except BudgetExceeded:
                raise
            except Exception as e:  # noqa: BLE001 - provider errors are heterogeneous
                last = e
                if attempt + 1 < retries:
                    time.sleep(backoff * (2 ** attempt))
    assert last is not None
    raise last


def chat(messages: list[dict], models: Sequence[str] | None = None, json_mode: bool = False, max_tokens: int = 4096, temperature: float = 0.2,
         thinking: bool | None = None) -> str:
    client = get_client()

    def _call(model, msgs, **_):
        kwargs = dict(model=model, messages=msgs, max_tokens=max_tokens, temperature=temperature)
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        if thinking is False:  # Nemotron reasons by default; the classifier needs an answer, not a deliberation
            kwargs["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
        resp = client.chat.completions.create(**kwargs)
        if getattr(resp, "usage", None) is not None:
            METER.add(model, resp.usage.prompt_tokens or 0, resp.usage.completion_tokens or 0)
        content = resp.choices[0].message.content or ""
        if not content.strip():
            raise RuntimeError(f"empty completion from {model}")
        return content

    return chat_with_fallback(_call, models or [WORKER_MODEL, FALLBACK_MODEL], messages)


def list_models() -> list[str]:
    return sorted(m.id for m in get_client().models.list().data)
