"""The studio: a one-page live demo served by the proxy at /studio.

Everything here runs on this host. Redaction uses the rules only (no model call), so typing in the page is free and
offline. Custom rules added in the page live in the request, never on disk: the visitor sees the effect at once and is
shown the three YAML lines to commit if they want to keep it. Only /studio/send talks to the configured upstream.
"""
from __future__ import annotations

import json
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Optional

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from .pii.guard import Guard
from .pii.rules import RuleSet

MAX_CUSTOM_RULES = 6
MAX_CUSTOM_PATTERN = 200
MAX_TEXT = 4000
_NAME_OK = re.compile(r"[^a-z0-9_]+")


# ---- turning one example into a rule ------------------------------------------------------------------------------
_SEP = {"-": "[-‑]", " ": r"\s", "/": "/", ".": r"\.", ":": ":", "_": "_", "#": "#"}


def suggest_pattern(example: str) -> str:
    """One example ID -> a regex for its shape. Letters stay literal (they are usually the fixed prefix, CLM / MBR),
    digit runs become \\d{n}, separators accept their common look-alikes. The visitor can edit the result."""
    example = example.strip()
    if not example:
        raise ValueError("type an example first")
    if len(example) > 60:
        raise ValueError("an example ID is at most 60 characters")
    parts: list[str] = []
    for run in re.findall(r"\d+|[A-Za-z]+|.", example):
        if run.isdigit():
            parts.append(rf"\d{{{len(run)}}}")
        elif run.isalpha():
            parts.append(re.escape(run))
        else:
            parts.append(_SEP.get(run, re.escape(run)))
    body = "".join(parts)
    start = r"\b" if re.match(r"\w", example) else ""
    end = r"\b" if re.search(r"\w$", example) else ""
    return f"{start}{body}{end}"


def _clean_name(name: str, fallback: str) -> str:
    n = _NAME_OK.sub("_", (name or "").strip().lower()).strip("_")[:40]
    return n or fallback


def custom_rules(raw: Any) -> list[dict]:
    """Validate rules sent by the page. Returns [{'name','pattern'}]; raises ValueError with a readable message."""
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise ValueError("rules must be a list")
    if len(raw) > MAX_CUSTOM_RULES:
        raise ValueError(f"at most {MAX_CUSTOM_RULES} custom rules in the studio")
    out = []
    for i, r in enumerate(raw):
        if not isinstance(r, dict):
            raise ValueError("each rule needs a name and a pattern")
        pattern = str(r.get("pattern", ""))
        if not pattern:
            raise ValueError("a rule needs a pattern")
        if len(pattern) > MAX_CUSTOM_PATTERN:
            raise ValueError(f"pattern longer than {MAX_CUSTOM_PATTERN} characters")
        out.append({"name": _clean_name(str(r.get("name", "")), f"custom_{i + 1}"), "pattern": pattern})
    return out


def rules_yaml_snippet(rules: list[dict]) -> str:
    return "".join(f"- 'name': '{r['name']}'\n  'pattern': '{r['pattern']}'\n" for r in rules)


def _with_custom(base: Guard, extra: list[dict]) -> Guard:
    """The base rules plus the page's rules, compiled through the same loader (so the ReDoS probe runs on them)."""
    if not extra:
        return Guard(base.rules, base.prompt, None)
    src = yaml.safe_load(base.rules.source) if base.rules.source else {"version": base.rules.version, "rules": []}
    rules = [r for r in src["rules"] if r["name"] not in {e["name"] for e in extra}] + extra
    text = yaml.safe_dump({"version": src.get("version", 0), "rules": rules}, sort_keys=False, allow_unicode=True)
    return Guard(RuleSet.from_yaml_text(text), base.prompt, None)


def _view(red) -> dict:
    return {"text": red.text, "tokens": [{"token": t, "value": v} for t, v in red.mapping.items()],
            "findings": [{"type": f.type, "value": f.value} for f in red.findings]}


# ---- the record of what the loop did -------------------------------------------------------------------------------
def _git_files(root: Path, ref: str) -> Optional[str]:
    import subprocess
    try:
        return subprocess.run(["git", "show", f"{ref}:guard/rules.yaml"], cwd=root, check=True, capture_output=True, text=True).stdout
    except Exception:  # noqa: BLE001 - not a git checkout (e.g. installed from a wheel)
        return None


def _rule_list(src: Optional[str]) -> list[dict]:
    if not src:
        return []
    return [{"name": r["name"], "pattern": r["pattern"]} for r in (yaml.safe_load(src) or {}).get("rules", [])]


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def _short(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    if len(s) <= n:
        return s
    cut = s[:n].rsplit(" ", 1)[0]
    return cut.rstrip(",;:.") + "…"


@lru_cache(maxsize=4)
def studio_record(root_s: str) -> dict:
    """Generations, the stage-by-stage story of one real round, and the held-out numbers. Read once, cached."""
    root = Path(root_s)
    hist = _jsonl(root / "runs" / "history.jsonl")
    tags = {}
    prev: list[dict] = _rule_list(_git_files(root, "gen-0"))
    gens = [{"gen": 0, "tag": "gen-0", "added": [r["name"] for r in prev], "rules": len(prev), "why": "Written by hand: SSN, email, US phone, card.",
             "val_before": None, "val_after": None}]
    for r in hist:
        if not r.get("accepted"):
            continue
        cur = _rule_list(_git_files(root, f"gen-{r['gen']}"))
        names_prev = {x["name"] for x in prev}
        added = [x["name"] for x in cur if x["name"] not in names_prev]
        gens.append({"gen": r["gen"], "tag": f"gen-{r['gen']}", "added": added, "rules": len(cur) or None,
                     "why": _short(r.get("rationale", ""), 150),
                     "val_before": r["val_before"]["leak_rate"], "val_after": r["val_after"]["leak_rate"]})
        tags[r["gen"]] = cur
        prev = cur or prev
    rejected = [r for r in hist if not r.get("accepted")]

    # one real round, told as four stages: the insurance round that produced gen-23
    stage = None
    r23 = next((r for r in hist if r["gen"] == 23 and r.get("accepted")), None)
    if r23:
        train = {a["id"]: a for a in _jsonl(root / "data" / "attacks-insurance" / "train.jsonl")}
        missed = [train[i] for i in r23["train_before"].get("missed_ids", []) if i in train]
        pick = []
        for tech in ("split_lines", "reversed", "rot13", "no_separators"):
            a = next((m for m in missed if m["technique"] == tech), None)
            if a:
                pick.append({"technique": tech.replace("_", " "), "text": a["text"], "leaked": a["surface_forms"][0]})
        by_tech = sorted(((k, v) for k, v in r23["train_before"]["by_technique"].items() if v > 0), key=lambda kv: -kv[1])
        before = {x["name"] for x in _rule_list(_git_files(root, "gen-22"))}
        added = [x for x in tags.get(23, []) if x["name"] not in before]
        nxt = next((r for r in hist if r["gen"] == 24), None)
        stage = {"gen": 23, "train_n": r23["train_before"]["n"], "train_leaks": r23["train_before"]["leaks"],
                 "attacks": pick[:3], "by_technique": [{"technique": k.replace("_", " "), "rate": v} for k, v in by_tech[:5]],
                 "added": added, "rationale": _short(r23.get("rationale", ""), 260),
                 "val_n": r23["val_before"]["n"], "val_before": r23["val_before"]["leak_rate"], "val_after": r23["val_after"]["leak_rate"],
                 "fp_before": r23["fp_before"]["fp_rate"], "fp_after": r23["fp_after"]["fp_rate"], "seconds": r23.get("seconds"),
                 "next": {"gen": nxt["gen"], "reason": nxt["reason"]} if nxt else None}

    rig = {}
    p = root / "runs" / "rigorous.json"
    if p.exists():
        d = json.loads(p.read_text())
        s = d["systems"]
        g0 = next((v for k, v in s.items() if "gen-0" in k), None)
        gn_key = next((k for k in s if "learned, no model" in k), None)
        if g0 and gn_key:
            gn = s[gn_key]
            rig = {"n": d["n_attacks"], "n_clean": d["n_clean"], "gen0_leaks": g0["strict_leaks"], "learned_leaks": gn["strict_leaks"],
                   "learned_fps": gn["fps"], "fixed": d["learning_effect"]["fixed"], "broken": d["learning_effect"]["broken"]}
    return {"generations": gens, "rounds": len(hist), "rejected": len(rejected), "stage": stage, "heldout": rig}


@lru_cache(maxsize=4)
def studio_examples(root_s: str) -> list[dict]:
    """Fresh attacks (values the loop never saw) that the hand-written rules leak and the learned rules stop."""
    root = Path(root_s)
    src0 = _git_files(root, "gen-0")
    if not src0:
        return []
    g0 = Guard.from_texts(src0)
    gn = Guard.from_dir(root / "guard")
    out, seen = [], set()
    for a in _jsonl(root / "data" / "attacks-fresh" / "heldout.jsonl"):
        text = a["text"]
        if a["technique"] in seen or len(text) > 120 or "\n" in text:
            continue
        sf = a["surface_forms"]
        r0, rn = g0.redact(text), gn.redact(text)
        # only examples the learned rules replace whole: a partly redacted value is still a leak
        if any(s in r0.text for s in sf) and sf[0] in rn.mapping.values():
            seen.add(a["technique"])
            out.append({"technique": a["technique"].replace("_", " "), "pii_type": a["pii_type"].replace("_", " "), "text": text,
                        "value": sf[0], "after": rn.text})
    return out


# ---- routes --------------------------------------------------------------------------------------------------------
def _model(allow: set[str]) -> Optional[str]:
    import os
    worker = os.environ.get("WORKER_MODEL", "nvidia/Nemotron-3.5-Lightning-30B-A3B")
    return worker if worker in allow else next(iter(sorted(allow)), None)


def mount_studio(app: FastAPI, *, root: Path, state: dict, auth: Callable, upstream: Any, allow: set[str]) -> None:
    gen0_src = _git_files(root, "gen-0")
    gen0 = Guard.from_texts(gen0_src) if gen0_src else None

    @app.get("/studio")
    def studio_page():
        html = (root / "piiguard" / "static" / "studio.html").read_text()
        # the public record (no secrets) is embedded, so the page renders without a token; live calls fill in the rest
        blob = json.dumps(_public_data()).replace("</", "<\\/")
        return HTMLResponse(html.replace("/*__STUDIO_DATA__*/null", blob))

    def _public_data() -> dict:
        g: Guard = state["guard"]
        rec = studio_record(str(root))
        base = getattr(upstream, "base", "") or ""
        return {**rec, "rules": {"version": g.rules.version, "count": len(g.rules.rules)},
                "examples": studio_examples(str(root)),
                "upstream": {"host": re.sub(r"^https?://", "", base).split("/")[0]},
                "model": _model(allow)}

    @app.get("/studio/data")
    def studio_data():
        return _public_data()

    assets = root / "piiguard" / "static" / "studio-assets"

    @app.get("/studio/assets/{name}")
    def studio_asset(name: str):
        from fastapi.responses import FileResponse
        path = (assets / name).resolve()
        if path.parent != assets.resolve() or path.suffix not in (".jpg", ".png", ".webp") or not path.is_file():
            raise HTTPException(404)
        return FileResponse(path, headers={"Cache-Control": "public, max-age=86400"})

    async def _body(request: Request) -> tuple[str, list[dict]]:
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            raise HTTPException(400, "send JSON")
        text = str(body.get("text", ""))[:MAX_TEXT]
        try:
            extra = custom_rules(body.get("rules"))
        except ValueError as e:
            raise HTTPException(400, str(e))
        return text, extra

    def _guard(extra: list[dict]) -> Guard:
        try:
            return _with_custom(state["guard"], extra)
        except ValueError as e:
            raise HTTPException(400, str(e))

    # Redaction in the studio is local compute on text the visitor typed: no token needed. Sending to the model costs
    # money and uses the provider key, so /studio/send keeps the proxy token.
    @app.post("/studio/redact")
    async def studio_redact(request: Request):
        text, extra = await _body(request)
        guard = _guard(extra)
        t0 = time.perf_counter()
        after = guard.redact(text)
        ms = round((time.perf_counter() - t0) * 1000, 2)
        before = gen0.redact(text) if gen0 is not None else None
        return {"before": _view(before) if before else None, "after": _view(after), "ms": ms,
                "rules": len(guard.rules.rules), "snippet": rules_yaml_snippet(extra) if extra else ""}

    @app.post("/studio/suggest")
    async def studio_suggest(request: Request):
        body = await request.json()
        example = str(body.get("example", ""))
        try:
            pattern = suggest_pattern(example)
            rule = custom_rules([{"name": body.get("name") or "", "pattern": pattern}])[0]
            Guard.from_texts(yaml.safe_dump({"version": 0, "rules": [rule]}))  # compiles + ReDoS probe
        except ValueError as e:
            raise HTTPException(400, str(e))
        return {"pattern": pattern, "name": rule["name"], "matches_example": bool(re.search(pattern, example.strip()))}

    @app.post("/studio/send", dependencies=[Depends(auth)])
    async def studio_send(request: Request):
        from .proxy import _redact_payload, _restore_response
        text, extra = await _body(request)
        guard = _guard(extra)
        model = _model(allow)
        payload = {"model": model, "max_tokens": 220, "messages": [
            {"role": "system", "content": "You are an internal assistant for authorized staff. Answer in two short sentences. Refer to any identifiers exactly as written."},
            {"role": "user", "content": text}]}
        if "crusoe" in (getattr(upstream, "base", "") or ""):
            payload["chat_template_kwargs"] = {"enable_thinking": False}  # Nemotron: answer, do not think aloud
        red, mapping, _ = _redact_payload(guard, payload, allow)
        left = red["messages"][-1]["content"]
        try:
            resp = upstream.chat(red)
        except Exception as e:  # noqa: BLE001 - show the failure in the page, never the upstream detail
            return {"left": left, "reply_raw": None, "reply": None, "error": f"the model could not be reached ({type(e).__name__})"}
        raw = ((resp.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        restored = _restore_response(resp, mapping)
        reply = ((restored.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        return {"left": left, "reply_raw": raw, "reply": reply, "error": None, "model": model}
