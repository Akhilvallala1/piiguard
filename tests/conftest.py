import pytest


@pytest.fixture(autouse=True)
def _isolate_proxy_events(tmp_path, monkeypatch):
    """Tests must never write into the real runs/ directory (the demo reads runs/proxy-events.jsonl)."""
    monkeypatch.setenv("PIIGUARD_EVENTS_PATH", str(tmp_path / "proxy-events.jsonl"))
