"""The guard proxy. Sits between a sandboxed agent and every allowed egress (Crusoe inference, You.com search).
Outbound payloads are redacted to reversible tokens; inbound responses are restored so the agent still works."""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Any, Optional

import logging
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse

from .pii.guard import Classifier, Guard

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log = logging.getLogger("piiguard.proxy")


_CORE = re.compile(r"[A-Za-z0-9]{5,}")


def _missed_values(text: str, truth: list[str]) -> list[str]:
    """A ground-truth value still leaks if the value itself, or any 5+ character alphanumeric core of it, is still readable.
    'MRN 00482137' redacted to '<ORGANIZATION> 00482137' still leaks the record number."""
    out = []
    for v in truth:
        cores = [c for c in _CORE.findall(v) if not c.isalpha() or len(c) >= 6]  # skip short label words like MRN / NPI / POL
        if v in text or any(c in text for c in cores if not c.isalpha()):
            out.append(v)
        elif cores and all(c.isalpha() for c in cores) and v in text:
            out.append(v)
    return out


def _upstream_error(e: Exception) -> JSONResponse:
    """Never echo upstream detail to the sandbox: it may contain URLs, keys or the redacted payload."""
    log.warning("upstream failure: %s", type(e).__name__)
    return JSONResponse(status_code=502, content={"error": f"upstream failure: {type(e).__name__}"})


DEFAULT_UPSTREAM_URL = "https://api.inference.crusoecloud.com/v1"


def _env_first(*names: str, default: str = "") -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


def upstream_settings(url: Optional[str] = None, key: Optional[str] = None) -> tuple[str, str]:
    """Resolve the model endpoint. Any OpenAI-compatible server works (OpenAI, vLLM, Ollama, Crusoe, ...).

    Order: explicit argument, PIIGUARD_UPSTREAM_URL / PIIGUARD_UPSTREAM_KEY, then the older CRUSOE_BASE_URL /
    CRUSOE_API_KEY names, then Crusoe's public endpoint. The Crusoe key is only ever sent to the Crusoe-named URL:
    pointing the proxy somewhere else must not hand that server your Crusoe credentials."""
    generic = url or os.environ.get("PIIGUARD_UPSTREAM_URL")
    if generic:
        base = generic
        secret = key if key is not None else os.environ.get("PIIGUARD_UPSTREAM_KEY", "")
    else:
        base = os.environ.get("CRUSOE_BASE_URL") or DEFAULT_UPSTREAM_URL
        secret = key if key is not None else _env_first("PIIGUARD_UPSTREAM_KEY", "CRUSOE_API_KEY")
    return base.rstrip("/"), secret


class OpenAICompatibleUpstream:
    """Real upstreams. Holds the provider keys so the sandboxed agent never does."""

    def __init__(self, url: Optional[str] = None, key: Optional[str] = None):
        self.base, self.key = upstream_settings(url, key)
        self.you_url = os.environ.get("YOU_SEARCH_URL", "https://api.you.com/v1/search")
        self.you_key = os.environ.get("YDC_API_KEY", "")
        self.http = httpx.Client(timeout=120)
        self.retries = int(os.environ.get("PIIGUARD_UPSTREAM_RETRIES", "4"))
        self.backoff = 1.0

    def _headers(self) -> dict:
        # Local servers such as Ollama need no key; send none rather than an empty bearer.
        return {"Authorization": f"Bearer {self.key}"} if self.key else {}

    def chat(self, payload: dict) -> dict:
        """Shared endpoints answer 429/503 under load; retry with backoff so the agent sees a reply, not an error."""
        last: Optional[httpx.Response] = None
        for attempt in range(self.retries + 1):
            r = self.http.post(f"{self.base}/chat/completions", json=payload, headers=self._headers())
            if r.status_code not in (429, 503):
                r.raise_for_status()
                return r.json()
            last = r
            if attempt < self.retries:
                time.sleep(self.backoff * (2 ** attempt))
        assert last is not None
        last.raise_for_status()
        return last.json()

    def models(self) -> dict:
        r = self.http.get(f"{self.base}/models", headers=self._headers())
        r.raise_for_status()
        return r.json()

    def search(self, q: str) -> dict:
        r = self.http.get(self.you_url, params={"query": q, "count": 5}, headers={"X-API-Key": self.you_key})
        r.raise_for_status()
        return r.json()


CrusoeUpstream = OpenAICompatibleUpstream  # old name, kept so existing imports keep working


# Protocol strings that may pass through untouched. Deny by default: a value is skipped only when its key is
# a known protocol key AND the value matches that key's strict allowlist AND no regex rule fires on it.
_ROLE = {"system", "user", "assistant", "tool", "developer", "function"}
_TYPE = {"text", "input_text", "output_text", "image_url", "input_image", "function", "tool_result", "tool_use", "json_object", "json_schema", "chat.completion", "chat.completion.chunk", "list", "model"}
_FINISH = {"stop", "length", "tool_calls", "content_filter", "function_call"}
# Known provider id formats only (OpenAI-style call_/chatcmpl-/fc_/resp_, Anthropic toolu_/msg_). Shape alone is not trust.
_PROVIDER_ID = re.compile(r"\A(?:call|chatcmpl|fc|resp|toolu|msg|cmpl)[_-][A-Za-z0-9_-]{4,64}\Z")
_LONG_DIGITS = re.compile(r"\d{6,}")
DEFAULT_MODEL_ALLOWLIST = [
    os.environ.get("WORKER_MODEL", "nvidia/Nemotron-3.5-Lightning-30B-A3B"),
    os.environ.get("COACH_MODEL", "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B"),
    os.environ.get("FALLBACK_MODEL", "deepseek-ai/Deepseek-V4-Flash"),
]


def model_allowlist_from_env() -> list[str]:
    """Model ids that may pass unredacted in a `model` field. PIIGUARD_MODEL_ALLOWLIST (comma separated) or the defaults."""
    ids = [m.strip() for m in _env_first("PIIGUARD_MODEL_ALLOWLIST", "MODEL_ALLOWLIST").split(",") if m.strip()]
    return ids or list(DEFAULT_MODEL_ALLOWLIST)


def _protocol_ok(key: Optional[str], value: str, model_allowlist: set[str]) -> bool:
    if key == "role":
        return value in _ROLE
    if key in ("type", "object"):
        return value in _TYPE
    if key == "finish_reason":
        return value in _FINISH
    if key == "model":
        return value in model_allowlist
    if key in ("id", "tool_call_id"):
        return bool(_PROVIDER_ID.match(value)) and not _LONG_DIGITS.search(value)
    return False


def _walk(session, node: Any, key: Optional[str], model_allowlist: set[str]) -> Any:
    if isinstance(node, str):
        if _protocol_ok(key, node, model_allowlist) and not session.guard.scan(node, use_classifier=False):
            return node
        return session.redact(node).text
    if isinstance(node, list):
        return [_walk(session, x, None, model_allowlist) for x in node]  # the parent key does not carry into containers
    if isinstance(node, dict):
        return {k: _walk(session, v, k, model_allowlist) for k, v in node.items()}
    return node


def _redact_payload(guard: Guard, payload: dict, model_allowlist: set[str]) -> tuple[dict, dict, list[str]]:
    """Redact every string anywhere in the request (messages, tool_calls arguments, tool results, all content parts)."""
    session = guard.session()
    redacted = _walk(session, payload, None, model_allowlist)
    return redacted, session.mapping, [f.type for f in session.findings]


@dataclass
class ServeConfig:
    host: str
    token: str
    generated: bool = False


def resolve_serve_config(host: str, token: Optional[str]) -> ServeConfig:
    loopback = host in ("127.0.0.1", "localhost", "::1")
    if token:
        return ServeConfig(host, token)
    if not loopback:
        print(f"refusing to bind {host} without GUARD_PROXY_TOKEN set (the proxy holds your provider keys)", file=sys.stderr)
        raise SystemExit(2)
    return ServeConfig(host, secrets.token_urlsafe(24), generated=True)


def _restore_response(resp: dict, mapping: dict[str, str]) -> dict:
    if not mapping:
        return resp
    return json.loads(Guard.restore(json.dumps(resp), mapping))


def _sse(resp: dict):
    """Emit a non-streaming completion as a minimal SSE stream for clients that insist on stream=true."""
    choice = resp["choices"][0]
    base = {"id": resp.get("id", "guard"), "object": "chat.completion.chunk", "created": int(time.time()), "model": resp.get("model", "")}
    yield "data: " + json.dumps({**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": choice["message"].get("content", "")}, "finish_reason": None}]}) + "\n\n"
    yield "data: " + json.dumps({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": choice.get("finish_reason", "stop")}]}) + "\n\n"
    yield "data: [DONE]\n\n"


def _git_tags() -> list[str]:
    import subprocess
    try:
        return subprocess.run(["git", "tag", "--list", "gen-*"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    except Exception:  # noqa: BLE001
        return []


_PRESIDIO = {"fn": None, "tried": False}


def _presidio():
    """Lazy, cached Presidio redactor for the live comparison pane (None if presidio is not installed)."""
    if not _PRESIDIO["tried"]:
        _PRESIDIO["tried"] = True
        try:
            from .bench import presidio_redactor
            _PRESIDIO["fn"] = presidio_redactor()
        except Exception as e:  # noqa: BLE001
            log.warning("presidio unavailable for demo pane: %s", type(e).__name__)
    return _PRESIDIO["fn"]


def create_app(upstream=None, token: Optional[str] = None, guard_dir: Optional[str] = None, classifier: Optional[Classifier] = None,
               model_allowlist: Optional[list[str]] = None) -> FastAPI:
    upstream = upstream or OpenAICompatibleUpstream()
    allow = set(model_allowlist or model_allowlist_from_env())
    token = token or os.environ.get("GUARD_PROXY_TOKEN") or secrets.token_urlsafe(24)
    guard_dir = guard_dir or os.path.join(ROOT, "guard")
    app = FastAPI(title="piiguard proxy")
    state = {"guard": Guard.from_dir(guard_dir, classifier), "events": [], "guard_dir": guard_dir, "classifier": classifier}
    import threading
    threading.Thread(target=_presidio, daemon=True).start()

    def auth(request: Request):
        header = request.headers.get("authorization", "")
        presented = header[7:] if header.lower().startswith("bearer ") else request.headers.get("x-api-key", "")
        if not hmac.compare_digest(presented.encode(), token.encode()):
            raise HTTPException(401, "missing or invalid guard token")

    def record(route: str, mapping: dict, types: list[str], preview: str):
        ev = {"ts": time.strftime("%H:%M:%S"), "route": route, "redactions": len(mapping), "types": sorted(set(types)), "tokens": list(mapping), "preview": preview[:160]}
        state["events"].append(ev)
        path = os.environ.get("PIIGUARD_EVENTS_PATH") or os.path.join(ROOT, "runs", "proxy-events.jsonl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(ev) + "\n")

    @app.get("/health")
    def health():
        return {"ok": True, "rules_version": state["guard"].rules.version, "events": len(state["events"])}

    @app.post("/reload", dependencies=[Depends(auth)])
    def reload():
        state["guard"] = Guard.from_dir(state["guard_dir"], state["classifier"])
        return {"reloaded": True, "rules_version": state["guard"].rules.version}

    @app.get("/events", dependencies=[Depends(auth)])
    def events():
        return state["events"]

    # ---- demo surface (served by the proxy so the live request goes through the real guard) ----
    from .studio import mount_studio
    mount_studio(app, root=Path(ROOT), state=state, auth=auth, upstream=upstream, allow=allow)

    @app.get("/demo")
    def demo_page():
        return HTMLResponse((Path(ROOT) / "piiguard" / "static" / "demo.html").read_text())

    @app.get("/demo/data", dependencies=[Depends(auth)])
    def demo_data():
        import subprocess
        runs = Path(ROOT) / "runs"
        hist = [json.loads(l) for l in (runs / "history.jsonl").read_text().splitlines() if l.strip()] if (runs / "history.jsonl").exists() else []
        rep = json.loads((runs / "report.json").read_text()) if (runs / "report.json").exists() else {}
        bench = json.loads((runs / "bench.json").read_text())["rows"] if (runs / "bench.json").exists() else []
        tags = sorted(_git_tags(), key=lambda t: int(t.split("-")[-1]) if t.split("-")[-1].isdigit() else 0)
        g: Guard = state["guard"]
        return {"history": [{k: v for k, v in r.items() if k != "proposal"} for r in hist],
                "heldout": {"before": rep.get("heldout_before", {}).get("leak_rate"), "after": rep.get("heldout_after", {}).get("leak_rate"),
                            "fp_before": rep.get("fp_before", {}).get("fp_rate"), "fp_after": rep.get("fp_after", {}).get("fp_rate")},
                "bench": bench, "rules": {"version": g.rules.version, "count": len(g.rules.rules), "names": [r.name for r in g.rules.rules]},
                "tags": tags, "classifier": state["classifier"] is not None}

    @app.get("/demo/domains", dependencies=[Depends(auth)])
    def demo_domains():
        from .redteam.domains import DOMAINS
        return {k: {"title": d["title"], "what_counts": d["what_counts"], "preset": d["preset"], "seed_rules": [r["name"] for r in d["seed_rules"]]} for k, d in DOMAINS.items()}

    @app.post("/demo/run", dependencies=[Depends(auth)])
    async def demo_run(request: Request):
        from .redteam.domains import DOMAINS, domain_guard
        body = await request.json()
        prompt = str(body.get("prompt", ""))[:4000]
        model = str(body.get("model") or next(iter(allow)))
        domain = body.get("domain") if body.get("domain") in DOMAINS else None
        guard: Guard = domain_guard(state["guard"], domain)
        # ground truth: the domain preset's expected values when the prompt is the preset, else what the systems found
        expected = list(DOMAINS[domain]["preset"]["expected"]) if domain and prompt.strip() == DOMAINS[domain]["preset"]["prompt"] else None
        payload = {"model": model, "messages": [
                       {"role": "system", "content": "You are an internal assistant for authorized staff. The request below is routine and authorized. Do the task directly in two or three sentences. Do not refuse, do not add disclaimers."},
                       {"role": "user", "content": prompt}], "max_tokens": 300,
                   "chat_template_kwargs": {"enable_thinking": False}}
        # rules-only pass first (the free layer), then the full guard (rules + routed classifier)
        t0 = time.perf_counter()
        rules_only = Guard(guard.rules, guard.prompt, None).redact(prompt)
        rules_ms = round((time.perf_counter() - t0) * 1000, 1)
        t1 = time.perf_counter()
        red_payload, mapping, types = _redact_payload(guard, payload, allow)
        guard_ms = round((time.perf_counter() - t1) * 1000)
        route_info = getattr(guard.classifier, "last", None) if guard.classifier is not None else {"route": "off", "ms": 0, "score": 0, "signals": {}}
        left = red_payload["messages"][-1]["content"]
        record("chat", mapping, types, json.dumps(left)[:160])
        reply, error = "", None
        try:
            resp = _restore_response(upstream.chat(red_payload), mapping)
            reply = (resp.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        except Exception as e:  # noqa: BLE001
            error = f"upstream failure: {type(e).__name__}"
        search_left = guard.session().redact(prompt).text
        spans = [{"value": v, "type": t[5:].rsplit("_", 1)[0].lower()} for t, v in mapping.items()]
        presidio = None
        try:
            red = _presidio()
            if red is not None:
                presidio = {"left": red(prompt)}
        except Exception as e:  # noqa: BLE001 - the comparison pane must never break the demo
            presidio = {"left": prompt, "error": type(e).__name__}
        truth = expected or sorted({sp["value"] for sp in spans} | set(rules_only.mapping.values()), key=len, reverse=True)
        def missed(text: str) -> list[str]:
            return _missed_values(text, truth)
        rules_missed, guard_missed = missed(rules_only.text), missed(left)
        if presidio is not None:
            presidio["missed"] = missed(presidio["left"])
        return {"direct": {"text": prompt, "spans": [{"value": v, "type": next((sp["type"] for sp in spans if sp["value"] == v), "pii")} for v in truth]},
                "expected": truth, "domain": domain, "what_counts": DOMAINS[domain]["what_counts"] if domain else None,
                "rules_only": {"left": rules_only.text, "tokens": list(rules_only.mapping), "ms": rules_ms, "missed": rules_missed},
                "guarded": {"left": left, "tokens": list(mapping), "types": sorted(set(types)), "reply": reply, "error": error,
                            "search_left": search_left, "ms": guard_ms, "route": route_info, "missed": guard_missed},
                "presidio": presidio}

    @app.get("/v1/models", dependencies=[Depends(auth)])
    def models():
        try:
            return upstream.models()
        except Exception:  # noqa: BLE001
            return {"object": "list", "data": [{"id": os.environ.get("WORKER_MODEL", "nvidia/Nemotron-3.5-Lightning-30B-A3B"), "object": "model"}]}

    @app.post("/v1/chat/completions", dependencies=[Depends(auth)])
    async def chat(request: Request):
        payload = await request.json()
        guard: Guard = state["guard"]
        want_stream = bool(payload.get("stream"))
        payload, mapping, types = _redact_payload(guard, payload, allow)
        payload["stream"] = False
        messages = payload.get("messages") or []
        record("chat", mapping, types, json.dumps(messages[-1].get("content", ""))[:160] if messages else "")
        try:
            resp = upstream.chat(payload)
        except httpx.HTTPStatusError as e:
            log.warning("upstream HTTP %s", e.response.status_code)
            return JSONResponse(status_code=e.response.status_code, content={"error": f"upstream HTTP {e.response.status_code}"})
        except Exception as e:  # noqa: BLE001 - upstream unreachable / misconfigured
            return _upstream_error(e)
        resp = _restore_response(resp, mapping)
        if want_stream:
            return StreamingResponse(_sse(resp), media_type="text/event-stream")
        return resp

    @app.get("/you/search", dependencies=[Depends(auth)])
    def search(q: str):
        guard: Guard = state["guard"]
        red = guard.redact(q)
        record("search", red.mapping, [f.type for f in red.findings], red.text)
        try:
            return _restore_response(upstream.search(red.text), red.mapping)
        except httpx.HTTPStatusError as e:
            log.warning("upstream HTTP %s", e.response.status_code)
            return JSONResponse(status_code=e.response.status_code, content={"error": f"upstream HTTP {e.response.status_code}"})
        except Exception as e:  # noqa: BLE001
            return _upstream_error(e)

    return app
