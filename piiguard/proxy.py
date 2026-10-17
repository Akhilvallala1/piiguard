"""The guard proxy. Sits between a sandboxed agent and every allowed egress (Crusoe inference, You.com search).
Outbound payloads are redacted to reversible tokens; inbound responses are restored so the agent still works."""
from __future__ import annotations

import hmac
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from typing import Any, Optional

import logging

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .pii.guard import Classifier, Guard

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log = logging.getLogger("piiguard.proxy")


def _upstream_error(e: Exception) -> JSONResponse:
    """Never echo upstream detail to the sandbox: it may contain URLs, keys or the redacted payload."""
    log.warning("upstream failure: %s", type(e).__name__)
    return JSONResponse(status_code=502, content={"error": f"upstream failure: {type(e).__name__}"})


class CrusoeUpstream:
    """Real upstreams. Holds the provider keys so the sandboxed agent never does."""

    def __init__(self):
        self.base = os.environ.get("CRUSOE_BASE_URL", "https://api.inference.crusoecloud.com/v1").rstrip("/")
        self.key = os.environ.get("CRUSOE_API_KEY", "")
        self.you_url = os.environ.get("YOU_SEARCH_URL", "https://api.ydc-index.io/v1/search")
        self.you_key = os.environ.get("YDC_API_KEY", "")
        self.http = httpx.Client(timeout=120)

    def chat(self, payload: dict) -> dict:
        r = self.http.post(f"{self.base}/chat/completions", json=payload, headers={"Authorization": f"Bearer {self.key}"})
        r.raise_for_status()
        return r.json()

    def models(self) -> dict:
        r = self.http.get(f"{self.base}/models", headers={"Authorization": f"Bearer {self.key}"})
        r.raise_for_status()
        return r.json()

    def search(self, q: str) -> dict:
        r = self.http.get(self.you_url, params={"query": q, "count": 5}, headers={"X-API-Key": self.you_key})
        r.raise_for_status()
        return r.json()


# Keys whose string values are protocol, not content. Everything else is inspected (deny by default).
_SKIP_KEYS = {"model", "role", "type", "id", "tool_call_id", "finish_reason", "object"}


def _walk(session, node: Any, key: Optional[str] = None) -> Any:
    if isinstance(node, str):
        return node if key in _SKIP_KEYS else session.redact(node).text
    if isinstance(node, list):
        return [_walk(session, x, key) for x in node]
    if isinstance(node, dict):
        return {k: _walk(session, v, k) for k, v in node.items()}
    return node


def _redact_payload(guard: Guard, payload: dict) -> tuple[dict, dict, list[str]]:
    """Redact every string anywhere in the request (messages, tool_calls arguments, tool results, all content parts)."""
    session = guard.session()
    redacted = _walk(session, payload)
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


def create_app(upstream=None, token: Optional[str] = None, guard_dir: Optional[str] = None, classifier: Optional[Classifier] = None) -> FastAPI:
    upstream = upstream or CrusoeUpstream()
    token = token or os.environ.get("GUARD_PROXY_TOKEN") or secrets.token_urlsafe(24)
    guard_dir = guard_dir or os.path.join(ROOT, "guard")
    app = FastAPI(title="piiguard proxy")
    state = {"guard": Guard.from_dir(guard_dir, classifier), "events": [], "guard_dir": guard_dir, "classifier": classifier}

    def auth(request: Request):
        header = request.headers.get("authorization", "")
        presented = header[7:] if header.lower().startswith("bearer ") else request.headers.get("x-api-key", "")
        if not hmac.compare_digest(presented.encode(), token.encode()):
            raise HTTPException(401, "missing or invalid guard token")

    def record(route: str, mapping: dict, types: list[str], preview: str):
        ev = {"ts": time.strftime("%H:%M:%S"), "route": route, "redactions": len(mapping), "types": sorted(set(types)), "tokens": list(mapping), "preview": preview[:160]}
        state["events"].append(ev)
        with open(os.path.join(ROOT, "runs", "proxy-events.jsonl"), "a") as f:
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

    @app.get("/v1/models", dependencies=[Depends(auth)])
    def models():
        try:
            return upstream.models()
        except Exception:  # noqa: BLE001
            return {"object": "list", "data": [{"id": os.environ.get("WORKER_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b"), "object": "model"}]}

    @app.post("/v1/chat/completions", dependencies=[Depends(auth)])
    async def chat(request: Request):
        payload = await request.json()
        guard: Guard = state["guard"]
        want_stream = bool(payload.get("stream"))
        payload, mapping, types = _redact_payload(guard, payload)
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
