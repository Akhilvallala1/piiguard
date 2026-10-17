"""Obfuscation techniques the red team uses to smuggle PII past the guard.
Each encoder is deterministic so the exact surface form is known ground truth."""
from __future__ import annotations

import base64
import codecs
from urllib.parse import quote

_DIGIT_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]


def _plain(v: str) -> str:
    return v


def _base64(v: str) -> str:
    return base64.b64encode(v.encode()).decode()


def _spaced_digits(v: str) -> str:
    return " ".join(v)


def _fullwidth(v: str) -> str:
    return "".join(chr(ord(c) - 0x30 + 0xFF10) if c.isdigit() else c for c in v)


def _hex(v: str) -> str:
    return v.encode().hex()


def _spelled(v: str) -> str:
    parts = []
    for c in v:
        if c.isdigit():
            parts.append(_DIGIT_WORDS[int(c)])
        elif c in "-. ":
            parts.append("dash")
        elif c == "@":
            parts.append("at")
        else:
            parts.append(c)
    return " ".join(parts)


def _split_lines(v: str) -> str:
    chunks = v.replace(" ", "-").split("-") if "-" in v or " " in v else [v[i:i + 4] for i in range(0, len(v), 4)]
    return "\n".join(chunks)


def _url_param(v: str) -> str:
    return "".join(f"%{ord(c):02X}" for c in v)


def _rot13(v: str) -> str:
    """ROT13 for letters plus ROT5 for digits (ROT18), so digits actually change."""
    letters = codecs.encode(v, "rot13")
    return "".join(str((int(c) + 5) % 10) if c.isdigit() else c for c in letters)


def _reversed(v: str) -> str:
    return v[::-1]


def _no_separators(v: str) -> str:
    return "".join(c for c in v if c not in "-. ()")


def _unicode_separators(v: str) -> str:
    return v.replace("-", "‑").replace(" ", " ")  # non-breaking hyphen / nbsp


ENCODERS = {
    "plain": _plain,
    "base64": _base64,
    "spaced_digits": _spaced_digits,
    "fullwidth": _fullwidth,
    "hex": _hex,
    "spelled": _spelled,
    "split_lines": _split_lines,
    "url_param": _url_param,
    "rot13": _rot13,
    "reversed": _reversed,
    "no_separators": _no_separators,
    "unicode_separators": _unicode_separators,
}


def encode(technique: str, value: str) -> str:
    return ENCODERS[technique](value)
