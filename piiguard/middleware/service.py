"""piiguard as an OpenShell supervisor middleware (RFC 0009, research preview).

This is the "plugin" form of the guard. Instead of the agent talking to our proxy, the agent talks to
Crusoe / You.com directly and the sandbox supervisor pauses each request to ask this service:

  HTTP_REQUEST  / PRE_CREDENTIALS  -> we redact the buffered body to typed tokens and hand back the replacement
  HTTP_RESPONSE / PRE_RETURN       -> we look the request up by request_id and restore the tokens in the reply

The guard itself is untouched: `Guard.session().redact()` on the way out, `Guard.restore()` on the way back.
Everything here is protocol plumbing around `proto/supervisor_middleware.proto` (vendored in ./proto).
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Optional

import grpc
from google.protobuf import json_format

from ..pii.guard import Guard
from ..proxy import DEFAULT_MODEL_ALLOWLIST, _walk
from .pb import extension_pb2 as ext
from .pb import supervisor_middleware_pb2 as pb
from .pb import supervisor_middleware_pb2_grpc as rpc

log = logging.getLogger("piiguard.middleware")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Protocol negotiation (docs/extensibility/overview: declare 1.0 and the contract capability).
PROTOCOL_MAJOR, PROTOCOL_MINOR = 1, 0
CONTRACT_CAPABILITY = "openshell.supervisor-middleware.contract"
IMPLEMENTATION_NAME = "piiguard/supervisor-middleware"
IMPLEMENTATION_VERSION = "0.1.0"
DEFAULT_MAX_PAYLOAD_BYTES = 1 << 20  # 1 MiB; the gateway registration may lower it, never raise it

PRE_CREDENTIALS = pb.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS
PRE_RETURN = pb.SUPERVISOR_MIDDLEWARE_PHASE_PRE_RETURN
WHOLE_BODY = pb.HTTP_RESPONSE_BODY_MODE_WHOLE_BODY_BYTES
STREAM_BODY = pb.HTTP_RESPONSE_BODY_MODE_STREAM_BYTES

# reason codes: lowercase ascii, digits, underscores, <= 64 bytes (returned to the sandbox on deny)
RC_PII = "pii_detected"
RC_BINARY = "piiguard_uninspectable_body"


# ----------------------------------------------------------------------------------------------------------------------
# policy `config:` for one network_middlewares entry
# ----------------------------------------------------------------------------------------------------------------------
@dataclass
class EntryConfig:
    mode: str = "redact"             # redact: replace values with tokens | deny: reject any request that carries PII
    restore: bool = True             # put the real values back into the response before the sandbox sees it
    identity_encoding: bool = True   # force `accept-encoding: identity` so the response body is inspectable (restore)
    on_binary: str = "deny"          # body that is not UTF-8 cannot be scanned: deny (fail closed) | allow

    KEYS = ("mode", "restore", "identity_encoding", "on_binary")

    @classmethod
    def parse(cls, struct) -> "EntryConfig":
        raw: dict[str, Any] = json_format.MessageToDict(struct) if struct is not None else {}
        unknown = sorted(set(raw) - set(cls.KEYS))
        if unknown:
            raise ValueError(f"unknown config keys: {', '.join(unknown)} (allowed: {', '.join(cls.KEYS)})")
        cfg = cls()
        if "mode" in raw:
            if raw["mode"] not in ("redact", "deny"):
                raise ValueError("mode must be 'redact' or 'deny'")
            cfg.mode = raw["mode"]
        for key in ("restore", "identity_encoding"):
            if key in raw:
                if not isinstance(raw[key], bool):
                    raise ValueError(f"{key} must be a boolean")
                setattr(cfg, key, raw[key])
        if "on_binary" in raw:
            if raw["on_binary"] not in ("deny", "allow"):
                raise ValueError("on_binary must be 'deny' or 'allow'")
            cfg.on_binary = raw["on_binary"]
        return cfg


# ----------------------------------------------------------------------------------------------------------------------
# request_id -> token mapping, so the response stage can restore what the request stage redacted
# ----------------------------------------------------------------------------------------------------------------------
class SessionStore:
    def __init__(self, ttl_s: float = 300.0, max_entries: int = 10_000):
        self.ttl_s = ttl_s
        self.max_entries = max_entries
        self._lock = threading.Lock()
        self._items: dict[str, tuple[float, dict[str, str]]] = {}

    def put(self, request_id: str, mapping: dict[str, str]) -> None:
        if not request_id or not mapping:
            return
        with self._lock:
            self._sweep()
            if len(self._items) >= self.max_entries:  # oldest out; a lost mapping only means tokens stay tokens
                self._items.pop(next(iter(self._items)))
            self._items[request_id] = (time.monotonic() + self.ttl_s, dict(mapping))

    def pop(self, request_id: str) -> Optional[dict[str, str]]:
        with self._lock:
            self._sweep()
            item = self._items.pop(request_id, None)
        return item[1] if item else None

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    def _sweep(self) -> None:
        now = time.monotonic()
        for k in [k for k, (exp, _) in self._items.items() if exp <= now]:
            del self._items[k]


# ----------------------------------------------------------------------------------------------------------------------
# the actual decision, protocol-free so it is easy to test
# ----------------------------------------------------------------------------------------------------------------------
@dataclass
class RequestOutcome:
    decision: int = pb.DECISION_ALLOW
    replacement: Optional[bytes] = None       # None: body unchanged
    mapping: dict[str, str] = field(default_factory=dict)
    findings: list = field(default_factory=list)   # guard Finding objects
    reason: str = ""
    reason_code: str = ""
    note: str = ""                            # non-secret diagnostic ("binary", "clean", ...)
    preview: str = ""                         # redacted text, safe to log


def _redact_text(guard: Guard, text: str, allow: set[str]):
    """JSON bodies are walked (every string: messages, tool args, tool results); anything else is one string."""
    session = guard.session()
    try:
        payload = json.loads(text)
    except ValueError:
        payload = None
    if isinstance(payload, (dict, list)):
        out = json.dumps(_walk(session, payload, None, allow), ensure_ascii=False)
    else:
        out = session.redact(text).text
    return out, session


def inspect_request(guard: Guard, body: bytes, cfg: EntryConfig, allow: Optional[set[str]] = None) -> RequestOutcome:
    allow = allow if allow is not None else set(DEFAULT_MODEL_ALLOWLIST)
    if not body:
        return RequestOutcome(note="empty")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        if cfg.on_binary == "allow":
            return RequestOutcome(note="binary_allowed")
        return RequestOutcome(decision=pb.DECISION_DENY, reason="body is not UTF-8; cannot be scanned", reason_code=RC_BINARY, note="binary")
    redacted, session = _redact_text(guard, text, allow)
    if not session.mapping:
        return RequestOutcome(note="clean", preview=redacted[:160])
    if cfg.mode == "deny":
        return RequestOutcome(decision=pb.DECISION_DENY, mapping=dict(session.mapping), findings=list(session.findings),
                              reason=f"{len(session.mapping)} PII value(s) in request body", reason_code=RC_PII, note="denied", preview=redacted[:160])
    return RequestOutcome(replacement=redacted.encode("utf-8"), mapping=dict(session.mapping), findings=list(session.findings),
                          reason=f"redacted {len(session.mapping)} PII value(s)", note="redacted", preview=redacted[:160])


def _pb_findings(findings: Iterable) -> list:
    """Audit-safe: type names and counts only, never the matched text."""
    counts: dict[tuple[str, str], int] = {}
    for f in findings:
        counts[(f.type, f.source)] = counts.get((f.type, f.source), 0) + 1
    out = []
    for (ftype, source), n in sorted(counts.items()):
        out.append(pb.Finding(type="pii", label=ftype, count=n, confidence="high" if source == "regex" else "medium", severity="high"))
    return out[:32]


def _record(event: dict) -> None:
    """Same JSONL the proxy writes, so `tail -1 runs/proxy-events.jsonl` shows what left the host either way."""
    path = os.environ.get("PIIGUARD_EVENTS_PATH") or os.path.join(ROOT, "runs", "proxy-events.jsonl")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:  # noqa: BLE001 - logging must never fail a decision
        log.warning("event log unavailable: %s", type(e).__name__)


# ----------------------------------------------------------------------------------------------------------------------
# gRPC services
# ----------------------------------------------------------------------------------------------------------------------
class PIIGuardMiddleware(rpc.SupervisorMiddlewareServicer):
    """Describe / ValidateConfig / EvaluateHttpRequest. WebSocket is not declared, so OpenShell never calls it."""

    def __init__(self, guard: Guard, store: Optional[SessionStore] = None, *, name: str = "piiguard",
                 max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES, model_allowlist: Optional[Iterable[str]] = None,
                 expected_audience: str = "", on_event: Optional[Callable[[dict], None]] = _record):
        self.guard = guard
        self.store = store if store is not None else SessionStore()
        self.name = name
        self.max_payload_bytes = int(max_payload_bytes)
        self.allow = set(model_allowlist) if model_allowlist is not None else set(DEFAULT_MODEL_ALLOWLIST)
        self.expected_audience = expected_audience
        self.on_event = on_event

    # -- negotiation -----------------------------------------------------------------------------------------------
    def manifest(self) -> pb.MiddlewareManifest:
        meta = ext.PeerMetadata(protocol_version=ext.ProtocolVersion(major=PROTOCOL_MAJOR, minor=PROTOCOL_MINOR),
                                implementation_name=IMPLEMENTATION_NAME, implementation_version=IMPLEMENTATION_VERSION,
                                supported_capabilities=[CONTRACT_CAPABILITY], required_capabilities=[CONTRACT_CAPABILITY])
        return pb.MiddlewareManifest(
            name=self.name, service_version=IMPLEMENTATION_VERSION, expected_audience=self.expected_audience, extension=meta,
            bindings=[
                pb.MiddlewareBinding(operation=pb.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST, phase=PRE_CREDENTIALS, max_payload_bytes=self.max_payload_bytes),
                pb.MiddlewareBinding(operation=pb.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_RESPONSE, phase=PRE_RETURN, max_payload_bytes=self.max_payload_bytes),
            ])

    def Describe(self, request, context):
        if not request.HasField("gateway"):
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, "gateway metadata is required")
        gw = request.gateway
        if gw.protocol_version.major != PROTOCOL_MAJOR:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION,
                          f"unsupported supervisor-middleware protocol {gw.protocol_version.major}.{gw.protocol_version.minor}; this service speaks {PROTOCOL_MAJOR}.{PROTOCOL_MINOR}")
        missing = sorted(set(gw.required_capabilities) - {CONTRACT_CAPABILITY})
        if missing:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"gateway requires unsupported capabilities: {', '.join(missing)}")
        if CONTRACT_CAPABILITY not in gw.supported_capabilities:
            context.abort(grpc.StatusCode.FAILED_PRECONDITION, f"gateway does not advertise {CONTRACT_CAPABILITY}")
        return self.manifest()

    def ValidateConfig(self, request, context):
        try:
            EntryConfig.parse(request.config)
        except ValueError as e:
            return pb.ValidateConfigResponse(valid=False, reason=str(e))
        return pb.ValidateConfigResponse(valid=True)

    # -- request stage ---------------------------------------------------------------------------------------------
    def EvaluateHttpRequest(self, request, context):
        if request.phase != PRE_CREDENTIALS:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"unsupported phase {request.phase}")
        try:
            cfg = EntryConfig.parse(request.config)
        except ValueError as e:
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
        if len(request.body) > self.max_payload_bytes:
            context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "request body exceeds the advertised payload limit")

        out = inspect_request(self.guard, request.body, cfg, self.allow)
        result = pb.HttpRequestResult(decision=out.decision, reason=out.reason, reason_code=out.reason_code,
                                      findings=_pb_findings(out.findings), metadata={"piiguard": out.note, "rules_version": str(self.guard.rules.version)})
        if out.decision == pb.DECISION_ALLOW and out.replacement is not None:
            result.has_body = True
            result.body = out.replacement
            if cfg.restore:
                self.store.put(request.context.request_id, out.mapping)
                if cfg.identity_encoding:
                    # A compressed response cannot be inspected by response middleware (docs: current limitations), so we
                    # ask upstream for identity encoding. `accept-encoding` is not a protected request header.
                    result.header_mutations.append(pb.HeaderMutation(write=pb.WriteHeader(
                        name="accept-encoding", value="identity", on_existing=pb.EXISTING_HEADER_ACTION_OVERWRITE)))
        if self.on_event is not None:
            self.on_event({"ts": time.strftime("%H:%M:%S"), "route": "middleware", "host": request.target.host, "path": request.target.path,
                           "sandbox": request.context.sandbox or request.context.sandbox_id, "decision": pb.Decision.Name(out.decision),
                           "redactions": len(out.mapping), "types": sorted({f.type for f in out.findings}), "tokens": list(out.mapping),
                           "preview": out.preview})
        return result

    def EvaluateWebSocketSession(self, request_iterator, context):
        context.abort(grpc.StatusCode.UNIMPLEMENTED, "piiguard does not declare the WEBSOCKET_MESSAGE binding")


class _ResponseSession:
    """State machine for one HttpResponsePreReturn.Evaluate stream: preflight -> body unit(s) -> trailers -> session_end."""

    def __init__(self, store: SessionStore, guard: Guard):
        self.store = store
        self.guard = guard
        self.mapping: Optional[dict[str, str]] = None
        self.mode: Optional[int] = None
        self.limit = 0
        self.seen_preflight = False
        self.body_ended = False
        self.trailers_seen = False
        self.last_seq = 0

    def preflight(self, pf: pb.HttpResponsePreflight) -> pb.HttpResponseEventResult:
        if self.seen_preflight:
            raise _Abort(grpc.StatusCode.FAILED_PRECONDITION, "duplicate preflight")
        self.seen_preflight = True
        try:
            cfg = EntryConfig.parse(pf.config)
        except ValueError as e:
            raise _Abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
        self.mapping = self.store.pop(pf.context.request_id) if cfg.restore else None
        skip = pb.HttpResponseEventResult(preflight_result=pb.HttpResponsePreflightResult(skip=pb.HttpResponsePreflightSkip()))
        if not self.mapping:
            skip.preflight_result.reason = "nothing to restore for this request"
            skip.preflight_result.metadata["piiguard"] = "no_mapping"
            return skip
        modes = set(pf.permitted_body_modes)
        self.mode = WHOLE_BODY if WHOLE_BODY in modes else STREAM_BODY if STREAM_BODY in modes else None
        self.limit = pf.max_payload_bytes
        if self.mode is None:
            # bodyless / compressed / partial / no-transform: tokens stay tokens in the agent's reply; say so in the audit log
            skip.preflight_result.reason = "response body is not inspectable; tokens left unrestored"
            skip.preflight_result.metadata["piiguard"] = "restore_unavailable"
            skip.preflight_result.findings.append(pb.Finding(type="piiguard_restore_skipped", label="uninspectable_response", count=1, severity="low"))
            return skip
        return pb.HttpResponseEventResult(preflight_result=pb.HttpResponsePreflightResult(
            inspect=pb.HttpResponsePreflightInspect(body_mode=self.mode), reason=f"restoring {len(self.mapping)} token(s)",
            metadata={"piiguard": "restore", "tokens": str(len(self.mapping))}))

    def body(self, unit: pb.HttpResponseBodyUnit) -> pb.HttpResponseEventResult:
        if self.mapping is None or self.mode is None:
            raise _Abort(grpc.StatusCode.FAILED_PRECONDITION, "body unit before an inspect decision")
        if self.body_ended or unit.sequence != self.last_seq + 1:
            raise _Abort(grpc.StatusCode.FAILED_PRECONDITION, f"unexpected body sequence {unit.sequence}")
        if self.mode == WHOLE_BODY and not unit.end_of_stream:
            raise _Abort(grpc.StatusCode.FAILED_PRECONDITION, "WHOLE_BODY_BYTES expects one final unit")
        self.last_seq = unit.sequence
        self.body_ended = unit.end_of_stream
        res = pb.HttpResponseBodyResult(sequence=unit.sequence)
        replacement = None
        try:
            text = unit.data.decode("utf-8")
            restored = Guard.restore(text, self.mapping)
            if restored != text:
                replacement = restored.encode("utf-8")
        except UnicodeDecodeError:
            res.metadata["piiguard"] = "unit_not_utf8"
        if replacement is not None and self.limit and len(replacement) > self.limit:
            replacement = None
            res.metadata["piiguard"] = "replacement_over_limit"
        if replacement is None:
            res.pass_through.SetInParent()
        else:
            res.transform.data = replacement
            res.metadata["piiguard"] = "restored"
        return pb.HttpResponseEventResult(body_result=res)

    def trailers(self) -> pb.HttpResponseEventResult:
        if not self.body_ended or self.trailers_seen:
            raise _Abort(grpc.StatusCode.FAILED_PRECONDITION, "trailers must follow the final body unit")
        self.trailers_seen = True
        return pb.HttpResponseEventResult(trailers_result=pb.HttpResponseTrailersResult())


class _Abort(Exception):
    def __init__(self, code: grpc.StatusCode, detail: str):
        super().__init__(detail)
        self.code, self.detail = code, detail


class PIIGuardResponses(rpc.HttpResponsePreReturnServicer):
    def __init__(self, guard: Guard, store: SessionStore):
        self.guard = guard
        self.store = store

    def Evaluate(self, request_iterator: Iterator[pb.HttpResponseEvent], context):
        sess = _ResponseSession(self.store, self.guard)
        try:
            for ev in request_iterator:
                kind = ev.WhichOneof("event")
                if kind == "preflight":
                    yield sess.preflight(ev.preflight)
                elif kind == "body":
                    yield sess.body(ev.body)
                elif kind == "trailers":
                    yield sess.trailers()
                elif kind == "session_end":
                    return
                else:
                    raise _Abort(grpc.StatusCode.INVALID_ARGUMENT, "response event is required")
        except _Abort as e:
            context.abort(e.code, e.detail)
