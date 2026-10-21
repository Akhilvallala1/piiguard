"""Hard-negative corpus: realistic agent traffic that is number-heavy but contains no PII.

25 hand-written clean samples cannot measure a false-positive rate below 4%. This builds 1,000+ deterministic samples
from templates covering what agents actually emit: logs, code, tool output, tables, metrics, URLs, timestamps,
versions, ids, money, coordinates, hashes. Every slot is filled with a value that looks like PII to a careless rule
(nine digits, sixteen digits, dashed groups, base64, hex) but is not.
"""
from __future__ import annotations

import base64
import random
import string

TEMPLATES = [
    "Order #{order} shipped on {date} and should arrive in {small}-{small2} business days.",
    "{ts} INFO worker-{small} processed batch {order} in {ms} ms (queue depth {small2})",
    "{ts} WARN retry {small}/5 for job {uuid} after HTTP {status}",
    "Commit {sha7} merged to main; build #{build} took {small}m {small2}s.",
    "SKU {sku} is out of stock; SKU {sku2} is the replacement.",
    "Invoice INV-{year}-{order} total ${money}, due net {net}.",
    "Upgraded {pkg} from {ver} to {ver2}; no breaking changes.",
    "| region | requests | p99 ms |\n|---|---|---|\n| us-east | {big} | {ms} |\n| eu-west | {big2} | {ms2} |",
    "Coordinates: {lat}, {lon} (warehouse {small}).",
    "Tracking number {tracking} is in transit.",
    "Set timeout_ms={ms} and max_retries={small} in config/{pkg}.yaml",
    "The checksum is sha256:{sha64}",
    "Cache key: {b64key}",
    "GET /api/v2/items/{order}?page={small}&limit={limit} 200 {ms}ms",
    "Room {room}, floor {small}; meeting starts at {hhmm}.",
    "Population of the metro area: {big} (census {year}).",
    "Ticket count by priority: P0 {small}, P1 {small2}, P2 {med}, P3 {med2}.",
    "Disk usage {pct}% on /dev/nvme0n1p{small}; {gb} GB free.",
    "Flight {airline} {flight} departs at {hhmm} from gate {gate}.",
    "Experiment {exp} improved conversion by {pct2} points (n={big}).",
    "Model {pkg}-{small}b scored {score} on the eval (seed {seed}).",
    "Serial range {serial}-{serial2} was recalled for firmware {ver}.",
    "Stack: File \"app/{pkg}.py\", line {line}, in handler\nKeyError: 'item_{order}'",
    "Run id {uuid} finished with exit code {exit}.",
    "Lot {lot} expires {date}; store below {temp} C.",
    "Account tier ENT-{small}{small2} includes {med} seats.",
    "Quarter revenue ${money}M, up {pct2}% year over year.",
    "Image digest {sha12} pushed to registry/{pkg}:{ver}",
    "Phone extension x{ext} routes to the {dept} desk.",
    "Postal batch {zip5} sorted at {hhmm}, {med} parcels.",
    "Matrix shape ({med}, {med2}, {small}) after reshape.",
    "Product barcode {ean13} scanned at aisle {small}.",
    "Version string {ver}-rc{small}+build.{build}",
    "Throughput {big} msgs/s over {small} partitions.",
    "Error budget remaining: {pct}% for {month} {year}.",
]

PKGS = ["pandas", "fastapi", "redis", "nginx", "torch", "grpc", "kafka", "postgres", "billing", "router", "ingest"]
AIRLINES = ["UA", "DL", "AA", "BA", "LH", "NH"]
DEPTS = ["billing", "support", "sales", "facilities", "IT"]
MONTHS = ["January", "March", "May", "July", "September", "November"]


def _ean13(rng):
    body = [rng.randint(0, 9) for _ in range(12)]
    s = sum(d * (3 if i % 2 else 1) for i, d in enumerate(body))
    return "".join(map(str, body)) + str((10 - s % 10) % 10)


def _not_luhn_16(rng):
    """16 digits that fail Luhn, so they are not card-shaped in the validated sense."""
    while True:
        d = [rng.randint(0, 9) for _ in range(16)]
        total = 0
        for i, x in enumerate(reversed(d)):
            if i % 2 == 1:
                x *= 2
                if x > 9:
                    x -= 9
            total += x
        if total % 10:
            return "".join(map(str, d))


def _fill(rng: random.Random) -> dict:
    hexd = string.hexdigits.lower()[:16]
    y = rng.randint(2019, 2026)
    return {
        "order": rng.randint(10000, 9999999), "date": f"{y}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
        "small": rng.randint(1, 9), "small2": rng.randint(2, 12), "med": rng.randint(20, 400), "med2": rng.randint(20, 400),
        "ts": f"{y}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}Z",
        "ms": rng.randint(3, 2400), "ms2": rng.randint(3, 2400), "status": rng.choice([429, 500, 502, 503, 504]),
        "uuid": "-".join("".join(rng.choice(hexd) for _ in range(k)) for k in (8, 4, 4, 4, 12)),
        "sha7": "".join(rng.choice(hexd) for _ in range(7)), "sha12": "".join(rng.choice(hexd) for _ in range(12)),
        "sha64": "".join(rng.choice(hexd) for _ in range(64)), "build": rng.randint(100, 99999),
        "sku": f"{rng.randint(1000,9999)}-{rng.randint(1000,9999)}", "sku2": f"{rng.randint(1000,9999)}-{rng.randint(1000,9999)}",
        "year": y, "money": f"{rng.randint(1,99):,}{rng.randint(0,999):03d}.{rng.randint(0,99):02d}" if rng.random() < .5 else f"{rng.randint(1,9999)}.{rng.randint(0,99):02d}",
        "net": rng.choice([15, 30, 45, 60]), "pkg": rng.choice(PKGS),
        "ver": f"{rng.randint(0,9)}.{rng.randint(0,30)}.{rng.randint(0,20)}", "ver2": f"{rng.randint(0,9)}.{rng.randint(0,30)}.{rng.randint(0,20)}",
        "big": f"{rng.randint(10000, 99999999):,}", "big2": f"{rng.randint(10000, 99999999):,}",
        "lat": f"{rng.uniform(-60, 60):.4f}", "lon": f"{rng.uniform(-170, 170):.4f}", "tracking": _not_luhn_16(rng),
        "b64key": base64.b64encode(rng.randbytes(18)).decode(), "limit": rng.choice([25, 50, 100, 250]),
        "room": rng.randint(100, 999), "hhmm": f"{rng.randint(0,23):02d}:{rng.randint(0,59):02d}", "pct": rng.randint(1, 99),
        "pct2": f"{rng.uniform(0.1, 9.9):.1f}", "gb": rng.randint(5, 900), "airline": rng.choice(AIRLINES), "flight": rng.randint(10, 9999),
        "gate": f"{rng.choice('ABCDEF')}{rng.randint(1,40)}", "exp": f"EXP-{rng.randint(100,9999)}", "score": f"{rng.uniform(0.2, 0.99):.3f}",
        "seed": rng.randint(0, 99999), "serial": f"SN{rng.randint(100000,999999)}", "serial2": f"SN{rng.randint(100000,999999)}",
        "line": rng.randint(1, 900), "exit": rng.choice([0, 1, 2, 137, 143]), "lot": f"L{rng.randint(10000,99999)}",
        "temp": rng.choice([4, 8, 25]), "ext": rng.randint(100, 9999), "dept": rng.choice(DEPTS),
        "zip5": f"{rng.randint(10000, 99999)}", "ean13": _ean13(rng), "month": rng.choice(MONTHS),
    }


def generate_clean(n: int = 1050, seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    out, seen = [], set()
    while len(out) < n:
        t = rng.choice(TEMPLATES).format(**_fill(rng))
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out
