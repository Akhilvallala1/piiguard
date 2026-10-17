"""The guard proxy. Sits between a sandboxed agent and every allowed egress (Crusoe inference, You.com search).
Outbound payloads are redacted to reversible tokens; inbound responses are restored so the agent still works."""
from __future__ import annotations

import json
import os
import time
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .pii.guard import Classifier, Guard

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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


def _redact_messages(guard: Guard, messages: list[dict]) -> tuple[list[dict], dict, list[str]]:
    mapping: dict[str, str] = {}
    types: list[str] = []
    out = []
    for m in messages:
        m = dict(m)
        content = m.get("content")
        if isinstance(content, str):
            red = guard.redact(content)
            m["content"], found = red.text, red
        elif isinstance(content, list):
            parts, found = [], None
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    red = guard.redact(part.get("text", ""))
                    part = {**part, "text": red.text}
                    mapping.update(red.mapping)
                    types += [f.type for f in red.findings]
                parts.append(part)
            m["content"] = parts
        else:
            found = None
        if found is not None:
            mapping.update(found.mapping)
            types += [f.type for f in found.findings]
        out.append(m)
    return out, mapping, types


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
    token = token or os.environ.get("GUARD_PROXY_TOKEN", "guard-dev-token")
    guard_dir = guard_dir or os.path.join(ROOT, "guard")
    app = FastAPI(title="piiguard proxy")
    state = {"guard": Guard.from_dir(guard_dir, classifier), "events": [], "guard_dir": guard_dir, "classifier": classifier}

    def auth(request: Request):
        header = request.headers.get("authorization", "")
        if header != f"Bearer {token}" and request.headers.get("x-api-key") != token:
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
        messages, mapping, types = _redact_messages(guard, payload.get("messages", []))
        want_stream = bool(payload.get("stream"))
        payload = {**payload, "messages": messages, "stream": False}
        record("chat", mapping, types, json.dumps(messages[-1].get("content", ""))[:160] if messages else "")
        try:
            resp = upstream.chat(payload)
        except httpx.HTTPStatusError as e:
            return JSONResponse(status_code=e.response.status_code, content={"error": e.response.text[:500]})
        except Exception as e:  # noqa: BLE001 - upstream unreachable / misconfigured
            return JSONResponse(status_code=502, content={"error": f"upstream failure: {e}"[:500]})
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
            return JSONResponse(status_code=e.response.status_code, content={"error": e.response.text[:500]})
        except Exception as e:  # noqa: BLE001
            return JSONResponse(status_code=502, content={"error": f"upstream failure: {e}"[:500]})

    return app
