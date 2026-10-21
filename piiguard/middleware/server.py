"""gRPC server bootstrap for the piiguard supervisor middleware: TLS, OpenShell extension-JWT verification, limits."""
from __future__ import annotations

import logging
import sys
from concurrent import futures
from dataclasses import dataclass
from typing import Callable, Optional

import grpc

from ..pii.guard import Guard
from .pb import supervisor_middleware_pb2_grpc as rpc
from .service import DEFAULT_MAX_PAYLOAD_BYTES, PIIGuardMiddleware, PIIGuardResponses, SessionStore

log = logging.getLogger("piiguard.middleware")
JWT_TYP = "openshell-ext+jwt"


@dataclass
class JwtAuth:
    """Verifies the short-lived Ed25519 token OpenShell attaches to every call (docs/extensibility/overview)."""
    key: object                  # cryptography Ed25519 public key, or a jwt.PyJWKSet
    gateway_id: str
    audience: str

    @classmethod
    def from_file(cls, path: str, gateway_id: str, audience: str) -> "JwtAuth":
        import jwt
        raw = open(path, "rb").read()
        if raw.lstrip().startswith(b"{"):
            key = jwt.PyJWKSet.from_json(raw.decode("utf-8"))
        else:
            from cryptography.hazmat.primitives import serialization
            key = serialization.load_pem_public_key(raw)
        return cls(key, gateway_id, audience)

    def verify(self, token: str) -> Optional[str]:
        """Returns None when valid, else a short failure reason (never echoed to the caller in detail)."""
        import jwt
        try:
            header = jwt.get_unverified_header(token)
            if header.get("typ") != JWT_TYP or header.get("alg") != "EdDSA":
                return "wrong typ/alg"
            key = self.key
            if isinstance(key, jwt.PyJWKSet):
                kid = header.get("kid")
                key = (key[kid] if kid else key.keys[0]).key
            claims = jwt.decode(token, key, algorithms=["EdDSA"], audience=self.audience, issuer=f"openshell-gateway:{self.gateway_id}",
                                options={"require": ["exp", "iat", "aud", "iss"]})
        except jwt.PyJWTError as e:
            return type(e).__name__
        if claims.get("caller_kind") not in ("gateway", "supervisor"):
            return "unknown caller_kind"
        if claims.get("caller_kind") == "supervisor" and not claims.get("sandbox_id"):
            return "supervisor token without sandbox_id"
        return None


class _AuthInterceptor(grpc.ServerInterceptor):
    def __init__(self, auth: JwtAuth):
        self.auth = auth

    def intercept_service(self, continuation, details):
        handler = continuation(details)
        if handler is None:
            return None
        md = {k.lower(): v for k, v in (details.invocation_metadata or ())}
        raw = md.get("authorization", "")
        token = raw[7:] if raw.lower().startswith("bearer ") else ""
        why = self.auth.verify(token) if token else "missing token"
        if why is None:
            return handler
        log.warning("rejected %s: %s", details.method, why)

        def deny_unary(_req, ctx):
            ctx.abort(grpc.StatusCode.UNAUTHENTICATED, "missing or invalid OpenShell extension token")

        def deny_stream(_it, ctx):
            ctx.abort(grpc.StatusCode.UNAUTHENTICATED, "missing or invalid OpenShell extension token")

        if handler.unary_unary:
            return grpc.unary_unary_rpc_method_handler(deny_unary, handler.request_deserializer, handler.response_serializer)
        if handler.unary_stream:
            return grpc.unary_stream_rpc_method_handler(deny_unary, handler.request_deserializer, handler.response_serializer)
        if handler.stream_unary:
            return grpc.stream_unary_rpc_method_handler(deny_stream, handler.request_deserializer, handler.response_serializer)
        return grpc.stream_stream_rpc_method_handler(deny_stream, handler.request_deserializer, handler.response_serializer)


def build_server(guard: Guard, *, store: Optional[SessionStore] = None, name: str = "piiguard", max_payload_bytes: int = DEFAULT_MAX_PAYLOAD_BYTES,
                 auth: Optional[JwtAuth] = None, workers: int = 16, on_event: Optional[Callable[[dict], None]] = None, **svc_kwargs) -> tuple[grpc.Server, PIIGuardMiddleware]:
    store = store if store is not None else SessionStore()
    kw = dict(name=name, max_payload_bytes=max_payload_bytes, expected_audience=auth.audience if auth else "", **svc_kwargs)
    if on_event is not None:
        kw["on_event"] = on_event
    mw = PIIGuardMiddleware(guard, store, **kw)
    # docs: raise the gRPC message limit to at least payload + 0.5 MiB so a maximum-size body still fits
    slack = 1 << 20
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=workers), interceptors=[_AuthInterceptor(auth)] if auth else [],
                         options=[("grpc.max_receive_message_length", max_payload_bytes + slack), ("grpc.max_send_message_length", max_payload_bytes + slack)])
    rpc.add_SupervisorMiddlewareServicer_to_server(mw, server)
    rpc.add_HttpResponsePreReturnServicer_to_server(PIIGuardResponses(guard, store), server)
    return server, mw


def serve(guard: Guard, host: str, port: int, *, tls_cert: Optional[str] = None, tls_key: Optional[str] = None, auth: Optional[JwtAuth] = None, **kw) -> None:
    server, mw = build_server(guard, auth=auth, **kw)
    addr = f"{host}:{port}"
    if tls_cert and tls_key:
        creds = grpc.ssl_server_credentials([(open(tls_key, "rb").read(), open(tls_cert, "rb").read())])
        bound = server.add_secure_port(addr, creds)
        scheme = "https"
    else:
        bound = server.add_insecure_port(addr)
        scheme = "http"
        print("plaintext gRPC: register with allow_insecure_transport = true (local development only)", file=sys.stderr)
    if not bound:
        print(f"could not bind {addr}", file=sys.stderr)
        raise SystemExit(2)
    print(f"piiguard supervisor middleware '{mw.name}' on {scheme}://{host}:{bound}  "
          f"(auth: {'jwt' if auth else 'off'}, max_payload_bytes: {mw.max_payload_bytes}, classifier: {'on' if guard.classifier else 'off'})", file=sys.stderr)
    server.start()
    server.wait_for_termination()
