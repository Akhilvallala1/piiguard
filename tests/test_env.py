import os
from piiguard.env import load_dotenv

def test_loads_quoted_values_and_does_not_override_existing(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text("# comment\nCRUSOE_API_KEY='abc$def'\nYDC_API_KEY=\"xyz\"\nPLAIN=1\nEXISTING=from_file\n")
    monkeypatch.delenv("CRUSOE_API_KEY", raising=False)
    monkeypatch.delenv("YDC_API_KEY", raising=False)
    monkeypatch.delenv("PLAIN", raising=False)
    monkeypatch.setenv("EXISTING", "from_shell")
    loaded = load_dotenv(f)
    assert os.environ["CRUSOE_API_KEY"] == "abc$def"
    assert os.environ["YDC_API_KEY"] == "xyz" and os.environ["PLAIN"] == "1"
    assert os.environ["EXISTING"] == "from_shell"
    assert set(loaded) == {"CRUSOE_API_KEY", "YDC_API_KEY", "PLAIN"}

def test_missing_file_is_fine(tmp_path):
    assert load_dotenv(tmp_path / "nope") == []
