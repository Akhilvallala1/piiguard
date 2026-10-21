"""The guard as an OpenShell supervisor middleware: real gRPC server on a loopback port, real generated stubs."""
import json
import time
from concurrent import futures
from pathlib import Path

import grpc
import pytest
from google.protobuf import struct_pb2

from piiguard.middleware import service as svc
from piiguard.middleware.pb import extension_pb2 as ext
from piiguard.middleware.pb import supervisor_middleware_pb2 as pb
from piiguard.middleware.pb import supervisor_middleware_pb2_grpc as rpc
from piiguard.middleware.server import JwtAuth, build_server
from piiguard.middleware.service import EntryConfig, SessionStore, inspect_request
from piiguard.pii.guard import Guard

GUARD_DIR = Path(__file__).resolve().parents[1] / "guard"
SSN, EMAIL = "912-34-5678", "maria.chen@example.com"


def _struct(d: dict) -> struct_pb2.Struct:
    s = struct_pb2.Struct()
    s.update(d)
    return s


def _gateway(major=1, minor=0, supported=(svc.CONTRACT_CAPABILITY,), required=()):
    return ext.PeerMetadata(protocol_version=ext.ProtocolVersion(major=major, minor=minor), implementation_name="openshell/gateway",
                            implementation_version="test", supported_capabilities=list(supported), required_capabilities=list(required))


def _ctx(request_id="req-1"):
    return pb.RequestContext(request_id=request_id, sandbox_id="sbx-1", sandbox="piiguard-agent", workspace="default")


def _target(host="api.inference.crusoecloud.com", path="/v1/chat/completions"):
    return pb.HttpRequestTarget(scheme="https", host=host, port=443, method="POST", path=path)


def _chat(content: str) -> bytes:
    return json.dumps({"model": "m", "messages": [{"role": "user", "content": content}]}).encode()


def _eval(body: bytes, config=None, request_id="req-1", phase=svc.PRE_CREDENTIALS):
    return pb.HttpRequestEvaluation(phase=phase, context=_ctx(request_id), config=_struct(config or {}), target=_target(), body=body, middleware_name="piiguard")


@pytest.fixture
def stack():
    """A live server with both services; yields (middleware stub, response stub, session store, events list)."""
    events = []
    store = SessionStore()
    server, _ = build_server(Guard.from_dir(GUARD_DIR), store=store, on_event=events.append, workers=4)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    try:
        yield rpc.SupervisorMiddlewareStub(channel), rpc.HttpResponsePreReturnStub(channel), store, events
    finally:
        channel.close()
        server.stop(None)


def _response_stream(resp_stub, request_id, body_units, modes=(pb.HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY, svc.WHOLE_BODY), config=None, limit=1 << 20):
    events = [pb.HttpResponseEvent(preflight=pb.HttpResponsePreflight(context=_ctx(request_id), target=_target(), status_code=200, config=_struct(config or {}),
                                                                      max_payload_bytes=limit, permitted_body_modes=list(modes),
                                                                      headers=[pb.HttpHeader(name="content-type", value="application/json")]))]
    for i, (data, end) in enumerate(body_units, start=1):
        events.append(pb.HttpResponseEvent(body=pb.HttpResponseBodyUnit(sequence=i, data=data, end_of_stream=end)))
    if body_units:
        events.append(pb.HttpResponseEvent(trailers=pb.HttpResponseTrailers()))
    events.append(pb.HttpResponseEvent(session_end=pb.MiddlewareSessionEnd(reason=pb.MIDDLEWARE_SESSION_END_REASON_NORMAL)))
    return list(resp_stub.Evaluate(iter(events)))


# ---- negotiation ------------------------------------------------------------------------------------------------------
def test_describe_declares_request_and_response_bindings(stack):
    mw, *_ = stack
    m = mw.Describe(pb.MiddlewareDescribeRequest(gateway=_gateway()))
    ops = {(b.operation, b.phase) for b in m.bindings}
    assert ops == {(pb.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_REQUEST, svc.PRE_CREDENTIALS), (pb.SUPERVISOR_MIDDLEWARE_OPERATION_HTTP_RESPONSE, svc.PRE_RETURN)}
    assert all(b.max_payload_bytes == svc.DEFAULT_MAX_PAYLOAD_BYTES for b in m.bindings)
    assert (m.extension.protocol_version.major, m.extension.protocol_version.minor) == (1, 0)
    assert svc.CONTRACT_CAPABILITY in m.extension.supported_capabilities
    assert m.name == "piiguard" and m.expected_audience == ""


def test_describe_rejects_incompatible_gateway(stack):
    mw, *_ = stack
    with pytest.raises(grpc.RpcError) as e:
        mw.Describe(pb.MiddlewareDescribeRequest(gateway=_gateway(major=2)))
    assert e.value.code() == grpc.StatusCode.FAILED_PRECONDITION
    with pytest.raises(grpc.RpcError) as e:
        mw.Describe(pb.MiddlewareDescribeRequest(gateway=_gateway(required=("openshell.something-new",))))
    assert e.value.code() == grpc.StatusCode.FAILED_PRECONDITION
    with pytest.raises(grpc.RpcError):
        mw.Describe(pb.MiddlewareDescribeRequest())  # no gateway metadata at all


def test_validate_config(stack):
    mw, *_ = stack
    assert mw.ValidateConfig(pb.ValidateConfigRequest(config=_struct({}), middleware_name="piiguard")).valid
    assert mw.ValidateConfig(pb.ValidateConfigRequest(config=_struct({"mode": "deny", "restore": False, "on_binary": "allow"}))).valid
    bad = mw.ValidateConfig(pb.ValidateConfigRequest(config=_struct({"mode": "shout"})))
    assert not bad.valid and "mode" in bad.reason
    bad = mw.ValidateConfig(pb.ValidateConfigRequest(config=_struct({"terms": ["x"]})))
    assert not bad.valid and "unknown config keys: terms" in bad.reason
    bad = mw.ValidateConfig(pb.ValidateConfigRequest(config=_struct({"restore": "yes"})))
    assert not bad.valid and "boolean" in bad.reason


# ---- request stage ----------------------------------------------------------------------------------------------------
def test_request_body_is_redacted_and_structure_kept(stack):
    mw, _, store, events = stack
    r = mw.EvaluateHttpRequest(_eval(_chat(f"Customer SSN {SSN}, email {EMAIL}")))
    assert r.decision == pb.DECISION_ALLOW and r.has_body
    out = json.loads(r.body)
    assert SSN not in r.body.decode() and EMAIL not in r.body.decode()
    assert out["messages"][0]["content"] == "Customer SSN [PII_SSN_1], email [PII_EMAIL_1]"
    assert out["model"] == "m" and out["messages"][0]["role"] == "user"
    labels = {(f.label, f.count) for f in r.findings}
    assert labels == {("ssn", 1), ("email", 1)} and all(f.type == "pii" for f in r.findings)
    assert all(SSN not in f.label and EMAIL not in f.label for f in r.findings)  # audit-safe
    # the mapping is parked for the response stage, and upstream is asked for an inspectable (identity) body
    assert len(store) == 1
    assert [(m.write.name, m.write.value, m.write.on_existing) for m in r.header_mutations] == [("accept-encoding", "identity", pb.EXISTING_HEADER_ACTION_OVERWRITE)]
    assert events[-1]["route"] == "middleware" and events[-1]["redactions"] == 2 and SSN not in json.dumps(events[-1])


def test_clean_request_passes_untouched(stack):
    mw, _, store, _ = stack
    r = mw.EvaluateHttpRequest(_eval(_chat("What is the capital of France?")))
    assert r.decision == pb.DECISION_ALLOW and not r.has_body and not r.header_mutations and not r.findings
    assert len(store) == 0
    r = mw.EvaluateHttpRequest(_eval(b""))
    assert r.decision == pb.DECISION_ALLOW and not r.has_body


def test_deny_mode_rejects_with_reason_code(stack):
    mw, _, store, _ = stack
    r = mw.EvaluateHttpRequest(_eval(_chat(f"SSN {SSN}"), {"mode": "deny"}))
    assert r.decision == pb.DECISION_DENY and r.reason_code == "pii_detected" and not r.has_body
    assert len(store) == 0


def test_non_json_text_body_is_redacted_as_one_string(stack):
    mw, *_ = stack
    r = mw.EvaluateHttpRequest(_eval(f"query={SSN}&n=5".encode()))
    assert r.has_body and r.body == b"query=[PII_SSN_1]&n=5"


def test_binary_body_fails_closed_unless_allowed(stack):
    mw, *_ = stack
    blob = bytes([0xFF, 0xFE, 0x00, 0x80]) * 4
    r = mw.EvaluateHttpRequest(_eval(blob))
    assert r.decision == pb.DECISION_DENY and r.reason_code == "piiguard_uninspectable_body"
    r = mw.EvaluateHttpRequest(_eval(blob, {"on_binary": "allow"}))
    assert r.decision == pb.DECISION_ALLOW and not r.has_body


def test_wrong_phase_and_bad_config_are_invalid_argument(stack):
    mw, *_ = stack
    with pytest.raises(grpc.RpcError) as e:
        mw.EvaluateHttpRequest(_eval(_chat("hi"), phase=svc.PRE_RETURN))
    assert e.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    with pytest.raises(grpc.RpcError) as e:
        mw.EvaluateHttpRequest(_eval(_chat("hi"), {"mode": "nope"}))
    assert e.value.code() == grpc.StatusCode.INVALID_ARGUMENT


def test_restore_disabled_keeps_nothing(stack):
    mw, _, store, _ = stack
    r = mw.EvaluateHttpRequest(_eval(_chat(f"SSN {SSN}"), {"restore": False}))
    assert r.has_body and len(store) == 0 and not r.header_mutations


# ---- response stage ---------------------------------------------------------------------------------------------------
def test_response_restores_tokens_whole_body(stack):
    mw, resp, store, _ = stack
    mw.EvaluateHttpRequest(_eval(_chat(f"Reply OK. Customer SSN {SSN}"), request_id="r1"))
    upstream = json.dumps({"choices": [{"message": {"role": "assistant", "content": "OK, noted [PII_SSN_1]."}}]}).encode()
    results = _response_stream(resp, "r1", [(upstream, True)])
    assert results[0].preflight_result.WhichOneof("action") == "inspect"
    assert results[0].preflight_result.inspect.body_mode == svc.WHOLE_BODY
    body = results[1].body_result
    assert body.sequence == 1 and body.WhichOneof("action") == "transform"
    assert json.loads(body.transform.data)["choices"][0]["message"]["content"] == f"OK, noted {SSN}."
    assert results[2].WhichOneof("result") == "trailers_result"
    assert len(results) == 3 and len(store) == 0  # mapping consumed


def test_response_without_mapping_is_skipped(stack):
    _, resp, *_ = stack
    results = _response_stream(resp, "never-seen", [])
    assert len(results) == 1 and results[0].preflight_result.WhichOneof("action") == "skip"


def test_response_passes_through_when_nothing_to_restore(stack):
    mw, resp, *_ = stack
    mw.EvaluateHttpRequest(_eval(_chat(f"SSN {SSN}"), request_id="r2"))
    results = _response_stream(resp, "r2", [(b'{"choices":[{"message":{"content":"no tokens here"}}]}', True)])
    assert results[1].body_result.WhichOneof("action") == "pass_through"


def test_response_stream_mode_restores_per_unit(stack):
    mw, resp, *_ = stack
    mw.EvaluateHttpRequest(_eval(_chat(f"SSN {SSN} and {EMAIL}"), request_id="r3"))
    units = [(b'data: {"delta":"[PII_SSN_1]"}\n\n', False), (b'data: {"delta":"plain"}\n\n', False), (b'data: {"delta":"[PII_EMAIL_1]"}\n\n', True)]
    results = _response_stream(resp, "r3", units, modes=(pb.HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY, svc.STREAM_BODY))
    assert results[0].preflight_result.inspect.body_mode == svc.STREAM_BODY
    actions = [r.body_result.WhichOneof("action") for r in results[1:4]]
    assert actions == ["transform", "pass_through", "transform"]
    assert SSN.encode() in results[1].body_result.transform.data and EMAIL.encode() in results[3].body_result.transform.data
    assert [r.body_result.sequence for r in results[1:4]] == [1, 2, 3]


def test_uninspectable_response_is_skipped_with_a_finding(stack):
    mw, resp, store, _ = stack
    mw.EvaluateHttpRequest(_eval(_chat(f"SSN {SSN}"), request_id="r4"))
    results = _response_stream(resp, "r4", [], modes=(pb.HTTP_RESPONSE_BODY_MODE_HEADERS_ONLY,))
    pf = results[0].preflight_result
    assert pf.WhichOneof("action") == "skip" and pf.findings[0].type == "piiguard_restore_skipped"
    assert len(store) == 0


def test_response_protocol_violation_aborts(stack):
    mw, resp, *_ = stack
    mw.EvaluateHttpRequest(_eval(_chat(f"SSN {SSN}"), request_id="r5"))
    events = [pb.HttpResponseEvent(body=pb.HttpResponseBodyUnit(sequence=1, data=b"x", end_of_stream=True))]  # body before preflight
    with pytest.raises(grpc.RpcError) as e:
        list(resp.Evaluate(iter(events)))
    assert e.value.code() == grpc.StatusCode.FAILED_PRECONDITION


def test_replacement_over_limit_passes_through(stack):
    mw, resp, *_ = stack
    mw.EvaluateHttpRequest(_eval(_chat(f"email {EMAIL}"), request_id="r6"))
    results = _response_stream(resp, "r6", [(b"[PII_EMAIL_1]", True)], limit=5)
    assert results[1].body_result.WhichOneof("action") == "pass_through" and results[1].body_result.metadata["piiguard"] == "replacement_over_limit"


# ---- pure pieces ------------------------------------------------------------------------------------------------------
def test_session_store_expires_and_bounds():
    s = SessionStore(ttl_s=0.01, max_entries=2)
    s.put("a", {"[T]": "v"})
    time.sleep(0.02)
    assert s.pop("a") is None
    s.put("b", {"[T]": "v"}); s.put("c", {"[T]": "v"}); s.put("d", {"[T]": "v"})
    assert len(s) == 2 and s.pop("b") is None and s.pop("d") == {"[T]": "v"}
    s.put("", {"[T]": "v"}); s.put("e", {})
    assert len(s) == 1


def test_inspect_request_same_value_same_token():
    g = Guard.from_dir(GUARD_DIR)
    out = inspect_request(g, _chat(f"{SSN} twice: {SSN}"), EntryConfig())
    assert out.replacement.decode().count("[PII_SSN_1]") == 2 and len(out.mapping) == 1


def test_config_parse_defaults():
    c = EntryConfig.parse(None)
    assert (c.mode, c.restore, c.identity_encoding, c.on_binary) == ("redact", True, True, "deny")


# ---- authentication ---------------------------------------------------------------------------------------------------
def _mint(priv, **claims):
    import jwt
    now = int(time.time())
    payload = {"iss": "openshell-gateway:gw-1", "aud": "urn:openshell:extension:middleware:piiguard", "sub": "gateway", "caller_kind": "gateway",
               "jti": "j1", "iat": now, "exp": now + 300, **claims}
    return jwt.encode(payload, priv, algorithm="EdDSA", headers={"typ": "openshell-ext+jwt", "kid": "k1"})


def test_jwt_interceptor_accepts_gateway_token_and_rejects_others(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (tmp_path / "gw.pem").write_bytes(pem)
    auth = JwtAuth.from_file(str(tmp_path / "gw.pem"), "gw-1", "urn:openshell:extension:middleware:piiguard")
    server, mw = build_server(Guard.from_dir(GUARD_DIR), auth=auth, on_event=lambda e: None, workers=2)
    port = server.add_insecure_port("127.0.0.1:0"); server.start()
    stub = rpc.SupervisorMiddlewareStub(grpc.insecure_channel(f"127.0.0.1:{port}"))
    req = pb.MiddlewareDescribeRequest(gateway=_gateway())
    try:
        with pytest.raises(grpc.RpcError) as e:
            stub.Describe(req)
        assert e.value.code() == grpc.StatusCode.UNAUTHENTICATED
        m = stub.Describe(req, metadata=(("authorization", f"Bearer {_mint(priv)}"),))
        assert m.expected_audience == "urn:openshell:extension:middleware:piiguard"
        sup = _mint(priv, caller_kind="supervisor", sandbox_id="sbx-1", sub="spiffe://openshell/sandbox/sbx-1")
        assert stub.EvaluateHttpRequest(_eval(_chat("hi")), metadata=(("authorization", f"Bearer {sup}"),)).decision == pb.DECISION_ALLOW
        for bad in (_mint(other), _mint(priv, aud="urn:openshell:extension:middleware:someone-else"), _mint(priv, iss="openshell-gateway:gw-2"),
                    _mint(priv, exp=int(time.time()) - 1), _mint(priv, caller_kind="supervisor")):
            with pytest.raises(grpc.RpcError) as e:
                stub.Describe(req, metadata=(("authorization", f"Bearer {bad}"),))
            assert e.value.code() == grpc.StatusCode.UNAUTHENTICATED
        # a sandbox bootstrap token signed by the same key but with the wrong typ must not pass
        import jwt
        bootstrap = jwt.encode({"iss": "openshell-gateway:gw-1", "aud": "urn:openshell:extension:middleware:piiguard", "iat": int(time.time()), "exp": int(time.time()) + 60,
                                "caller_kind": "gateway"}, priv, algorithm="EdDSA", headers={"typ": "JWT"})
        with pytest.raises(grpc.RpcError):
            stub.Describe(req, metadata=(("authorization", f"Bearer {bootstrap}"),))
    finally:
        server.stop(None)
