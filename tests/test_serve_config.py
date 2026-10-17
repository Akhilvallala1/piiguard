import pytest
from piiguard.proxy import resolve_serve_config

def test_loopback_without_token_generates_random_token():
    cfg = resolve_serve_config(host="127.0.0.1", token=None)
    assert cfg.host == "127.0.0.1" and len(cfg.token) >= 24 and cfg.generated

def test_non_loopback_without_token_is_refused():
    with pytest.raises(SystemExit):
        resolve_serve_config(host="0.0.0.0", token=None)

def test_explicit_token_is_kept():
    assert resolve_serve_config(host="0.0.0.0", token="abc").token == "abc"
