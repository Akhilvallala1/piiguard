"""Fresh-value evaluation sets: synthetic people the coach never saw, wrapped in carrier templates it never saw.

The original held-out split shares people (and so exact SSNs, phones, cards) with train, and uses the same ten carrier
templates. A rule that memorized a value, or a carrier shape, would look like it generalized. This module builds an
evaluation set where every value is new and every carrier is new, deterministically from a seed, with no model calls.

All values stay inside reserved or never-issued ranges:
  SSN     area 900-999 (never issued)
  phone   NXX-555-0100..0199 (the 555-01xx line block is reserved for fiction)
  card    random digits with a valid Luhn check digit and test-only BIN prefixes
  email   example.com / example.org / example.net (RFC 2606)
"""
from __future__ import annotations

import random

from .encoders import ENCODERS, encode
from .generator import LABELS, _render

FIRST = ["Nora", "Ibrahim", "Keiko", "Mateo", "Zanele", "Oskar", "Leila", "Rafael", "Ana", "Dmitri", "Chioma", "Hiro",
         "Fatima", "Bjorn", "Mei", "Santiago", "Amara", "Yusuf", "Elena", "Kwame", "Sofia", "Arjun", "Ines", "Tariq"]
LAST = ["Lindqvist", "Haddad", "Tanaka", "Silva", "Dlamini", "Novak", "Farouk", "Ortega", "Petrova", "Mensah",
        "Nakamura", "Rahman", "Costa", "Eriksen", "Zhou", "Alvarez", "Obi", "Kaya", "Rossi", "Asante", "Patel", "Weber"]
DOMAINS = ["example.com", "example.org", "example.net"]
CARD_PREFIXES = ["4000", "4242", "5200", "5454", "2223", "3714", "6011"]

# Carriers the coach never saw: different agent outputs, different phrasing, different field names.
FRESH_CARRIERS = {
    "sql_insert": "INSERT INTO customers (full_name, {key}) VALUES ('{name}', '{pii}');",
    "yaml_config": "customer:\n  display: {name}\n  {key}: \"{pii}\"\n  tier: gold",
    "csv_row": "id,name,{key},region\n7731,{name},{pii},emea",
    "graphql": "mutation {{ updateProfile(name: \"{name}\", {key}: \"{pii}\") {{ ok }} }}",
    "slack_message": "@here quick one, {first} asked us to double check their {label} ({pii}) before the renewal call",
    "stack_trace": "Traceback (most recent call last):\n  File \"billing.py\", line 88, in charge\nValueError: rejected {label} {pii} for {name}",
    "voice_transcript": "[00:02:14] caller: yeah it's {name}, and my {label} should be {pii}",
    "http_header": "POST /v2/verify HTTP/1.1\nX-Customer: {name}\nX-{key}: {pii}\nContent-Length: 0",
    "spreadsheet_note": "Row 14 ({name}): {label} = {pii}; flagged by finance",
    "commit_message": "fix: stop logging {label} for {first} ({pii}) in the retry path",
}


def _luhn_digit(body: str) -> str:
    total = 0
    for i, c in enumerate(reversed(body)):
        d = int(c)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def fresh_person(rng: random.Random, taken: set[str]) -> dict:
    while True:
        first, last = rng.choice(FIRST), rng.choice(LAST)
        name = f"{first} {last}"
        ssn = f"{rng.randint(900, 999)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"
        if name not in taken and ssn not in taken:
            break
    # Valid 10-digit US shape in the fictional block: any area code, exchange 555, line 0100-0199
    area, line = rng.randint(201, 989), rng.randint(100, 199)
    fmt = rng.choice(["{a}-555-{l:04d}", "({a}) 555-{l:04d}", "{a}.555.{l:04d}", "+1 {a}-555-{l:04d}", "{a} 555 {l:04d}"])
    phone = fmt.format(a=area, l=line)
    body = rng.choice(CARD_PREFIXES) + "".join(str(rng.randint(0, 9)) for _ in range(11))
    digits = body + _luhn_digit(body)
    card = " ".join(digits[i:i + 4] for i in range(0, 16, 4))
    dob = f"{rng.randint(1, 12):02d}/{rng.randint(1, 28):02d}/{rng.randint(1950, 2004)}"
    email = f"{first.lower()}.{last.lower()}{rng.randint(1, 99)}@{rng.choice(DOMAINS)}"
    taken.update({name, ssn})
    return {"name": name, "ssn": ssn, "email": email, "phone": phone, "credit_card": card, "dob": dob}


def generate_fresh(n: int, seed: int = 1000, techniques=None, pii_types=None, exclude_values: set[str] | None = None,
                   carriers: dict | None = None) -> list[dict]:
    """n attacks, every PII value new (and not in exclude_values), carriers from FRESH_CARRIERS unless given."""
    rng = random.Random(seed)
    techniques = techniques or list(ENCODERS)
    pii_types = pii_types or list(LABELS)
    exclude = set(exclude_values or ())
    taken: set[str] = set(exclude)
    people = [fresh_person(rng, taken) for _ in range(max(8, n // 4))]
    carriers = list((carriers or FRESH_CARRIERS).items())
    out = []
    for i in range(n):
        person, pii_type, technique = rng.choice(people), rng.choice(pii_types), rng.choice(techniques)
        value = person[pii_type]
        if value in exclude:
            continue
        surface = encode(technique, value)
        if surface == value:
            technique = "plain"
        carrier_name, template = rng.choice(carriers)
        out.append({"id": f"fresh-{seed}-{i:04d}", "technique": technique, "pii_type": pii_type, "carrier": carrier_name,
                    "text": _render(template, person, pii_type, surface), "surface_forms": [surface], "plain_value": value})
    return out
