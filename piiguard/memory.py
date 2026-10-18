"""Shape memory: every identifier shape the guard has ever caught, with the rule and generation that caught it.
Two uses:
  - regression gate: a proposed rule set must still catch every remembered shape (the validation sample is small)
  - precedents: when a new shape leaks, show the coach the nearest remembered shapes and the rules that solved them
Shapes are compared by signature (digits -> 9, letters -> A, separators kept) with character-trigram similarity.
Identifiers are near each other because of shape, not meaning, so no embedding model is needed or wanted here."""
from __future__ import annotations

import json
from pathlib import Path

from .pii.guard import Guard


def signature(s: str) -> str:
    out = []
    for ch in s:
        if ch.isdigit():
            out.append("9")
        elif ch.isalpha():
            out.append("A")
        else:
            out.append(ch)
    return "".join(out)


def _trigrams(s: str) -> set[str]:
    s = f"^{s}$"
    return {s[i:i + 3] for i in range(len(s) - 2)} if len(s) >= 3 else {s}


def similarity(a: str, b: str) -> float:
    ta, tb = _trigrams(signature(a)), _trigrams(signature(b))
    return len(ta & tb) / max(1, len(ta | tb))


class ShapeLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.entries: list[dict] = []
        if self.path.exists():
            self.entries = [json.loads(l) for l in self.path.read_text().splitlines() if l.strip()]

    def _known(self) -> set[str]:
        return {e["surface"] for e in self.entries}

    def record(self, guard: Guard, attacks: list[dict], gen: int) -> int:
        """Remember every surface form the guard catches (regex layer), attributed to the rule that fired."""
        known = self._known()
        added = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            for a in attacks:
                findings = guard.scan(a["text"], use_classifier=False)
                for sf in a["surface_forms"]:
                    if sf in known:
                        continue
                    hit = next((fi for fi in findings if a["text"][fi.start:fi.end] == sf or sf in a["text"][fi.start:fi.end]), None)
                    if hit is None:
                        continue
                    e = {"surface": sf, "signature": signature(sf), "pii_type": a.get("pii_type"), "technique": a.get("technique"), "rule": hit.type, "gen": gen, "text": a["text"][:200]}
                    f.write(json.dumps(e) + "\n")
                    self.entries.append(e)
                    known.add(sf)
                    added += 1
        return added

    def regressions(self, candidate: Guard) -> list[dict]:
        """Remembered shapes the candidate rules would no longer catch."""
        lost = []
        for e in self.entries:
            red = Guard(candidate.rules, candidate.prompt, None).redact(e["text"])
            if e["surface"] in red.text:
                lost.append(e)
        return lost

    def precedents(self, surface: str, k: int = 5) -> list[dict]:
        scored = sorted(({**e, "score": round(similarity(surface, e["surface"]), 3)} for e in self.entries), key=lambda x: -x["score"])
        return scored[:k]
