from piiguard.pii.rules import RuleSet, VALIDATOR_DOCS
from piiguard.pii.guard import Guard

BASE = """version: 1
rules:
  - name: ssn
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
  - name: email
    pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b'
"""

def make(extra):
    return Guard(RuleSet.from_yaml_text(BASE + extra))

def test_base64_validator_only_fires_when_decoded_text_contains_pii():
    g = make("  - name: b64\n    pattern: '\\b[A-Za-z0-9+/]{12,}={0,2}'\n    validator: decodes_to_pii_base64\n")
    assert g.redact("ssn OTEyLTM0LTU2Nzg= here").text == "ssn [PII_B64_1] here"          # 912-34-5678
    assert g.redact("blob aGVsbG8gd29ybGQgZm9v here").text == "blob aGVsbG8gd29ybGQgZm9v here"  # 'hello world foo'

def test_reversed_validator():
    g = make("  - name: rev\n    pattern: '\\b[\\w.@-]{9,}\\b'\n    validator: reversed_is_pii\n")
    assert g.redact("x 8765-43-219 y").text == "x [PII_REV_1] y"                      # 912-34-5678 reversed
    assert "moc.elpmaxe" not in g.redact("x moc.elpmaxe@nehc.airam y").text            # email reversed (plain email rule may win)
    assert g.redact("x dlrowolleh y").text == "x dlrowolleh y"                         # reversed text that is not PII

def test_normalized_validator_collapses_separators_and_fullwidth():
    g = make("  - name: obf\n    pattern: '[\\d０-９](?:[\\s\\u00a0\\u2011._-]*[\\d０-９]){8}'\n    validator: normalized_is_pii\n")
    assert "９１２" not in g.redact("ssn ９１２-３４-５６７８").text
    assert g.redact("ssn 9 1 2 - 3 4 - 5 6 7 8").text == "ssn [PII_OBF_1]"
    assert g.redact("order 20261017 shipped").text == "order 20261017 shipped"        # 8 digits, no dob rule in BASE

def test_hex_and_url_validators():
    g = make("  - name: hx\n    pattern: '\\b[0-9a-f]{16,}\\b'\n    validator: decodes_to_pii_hex\n  - name: url\n    pattern: '(?:%[0-9A-Fa-f]{2}){6,}'\n    validator: decodes_to_pii_url\n")
    assert g.redact("h " + "912-34-5678".encode().hex()).text == "h [PII_HX_1]"
    assert g.redact("u %39%31%32%2D%33%34%2D%35%36%37%38").text == "u [PII_URL_1]"

def test_validator_docs_cover_every_validator():
    from piiguard.pii.rules import VALIDATORS
    assert set(VALIDATOR_DOCS) == set(VALIDATORS)


def test_timeout_inside_a_decoder_validator_fails_closed():
    from piiguard.pii.rules import Rule
    class Hang:
        pattern = "x"
        def finditer(self, text, timeout=None):
            raise TimeoutError("regex timeout")
    g = make("  - name: b64\n    pattern: '\\b[A-Za-z0-9+/]{12,}={0,2}'\n    validator: decodes_to_pii_base64\n")
    g.rules.rules.insert(0, Rule(name="hang", pattern="x", regex=Hang()))  # a plain rule that hangs
    red = g.redact("blob OTEyLTM0LTU2Nzg= here")
    assert red.text == "[PII_SCAN_TIMEOUT_1]"

def test_base64_with_invalid_utf8_byte_and_urlsafe_alphabet_still_detected():
    import base64
    g = make("  - name: b64\n    pattern: '[A-Za-z0-9+/_-]{12,}={0,2}'\n    validator: decodes_to_pii_base64\n")
    dirty = base64.b64encode(b"\xff ssn 912-34-5678").decode()           # leading invalid utf-8 byte
    assert dirty not in g.redact("x " + dirty + " y").text
    urlsafe = base64.urlsafe_b64encode(b"maria.chen@example.com?").decode()  # produces '-' or '_' chars
    assert urlsafe not in g.redact("x " + urlsafe + " y").text
