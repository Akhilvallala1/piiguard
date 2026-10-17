from piiguard.redteam.encoders import ENCODERS, encode

def test_registry_has_baseline_techniques():
    assert {"plain", "base64", "spaced_digits", "fullwidth", "hex", "spelled", "split_lines", "url_param", "rot13"} <= set(ENCODERS)

def test_base64_surface_form_is_decodable_and_distinct():
    out = encode("base64", "123-45-6789")
    assert out != "123-45-6789"
    import base64
    assert base64.b64decode(out).decode() == "123-45-6789"

def test_spaced_digits_only_spaces_digits():
    assert encode("spaced_digits", "123-45-6789") == "1 2 3 - 4 5 - 6 7 8 9"

def test_fullwidth_maps_ascii_digits():
    assert encode("fullwidth", "42") == "４２"
