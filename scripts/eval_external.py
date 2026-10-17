"""External check on NVIDIA's Nemotron-PII test split (CC-BY-4.0): data we did not make.
Entity-level recall per system (a ground-truth span counts as caught if neither the span nor its 5+ char alphanumeric
core survives the redaction) plus record-level leak rate (any span survived). Domains map to our industry packs where one exists."""
from __future__ import annotations

import ast
import json
import os
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from piiguard.bench import presidio_redactor  # noqa: E402
from piiguard.coach.gate import GuardRepo  # noqa: E402
from piiguard.env import load_dotenv  # noqa: E402
from piiguard.pii.guard import Guard  # noqa: E402
from piiguard.proxy import _missed_values  # noqa: E402
from piiguard.redteam.domains import DOMAINS, domain_guard  # noqa: E402

load_dotenv()
N = int(os.environ.get("EXT_N", "300"))
SEED = 7
import re
# Structured identifiers: what a regex-first guard is built for. Names, places, companies, times are semantic PII (classifier territory).
HARD = re.compile(r"ssn|social|card|routing|account|iban|passport|licen|customer_id|employee_id|member|mrn|medical|npi|policy|claim|phone|email|ip_address|mac_address|vin|date_of_birth|dob|tax|ein|swift|bic|api_key|password|username|user_id|device|imei|plate|cvv|pin\b|iban|bank", re.I)
DOMAIN_MAP = {"finance": "finance", "healthcare": "healthcare", "health": "healthcare", "legal": "legal", "law": "legal", "insurance": "insurance"}


def pack_for(domain: str) -> str | None:
    d = (domain or "").lower()
    for k, v in DOMAIN_MAP.items():
        if k in d:
            return v
    return None


def main():
    df = pd.read_parquet(ROOT / "data/external/nemotron-pii/test.parquet")
    df = df[df["locale"] == "us"] if (df["locale"] == "us").any() else df
    # stratified sample across domains
    per = max(1, N // df["domain"].nunique())
    parts = [g.sample(min(len(g), per), random_state=SEED) for _, g in df.groupby("domain")]
    sample = pd.concat(parts).sample(frac=1, random_state=SEED).head(N)
    records = []
    for _, r in sample.iterrows():
        spans = ast.literal_eval(r["spans"]) if isinstance(r["spans"], str) else list(r["spans"])
        records.append({"uid": r["uid"], "domain": r["domain"], "text": r["text"], "spans": [{"text": str(s["text"]), "label": str(s["label"])} for s in spans if s.get("text") not in (None, "")]})
    print(f"records: {len(records)} across {sample['domain'].nunique()} domains; entities: {sum(len(x['spans']) for x in records)}", file=sys.stderr)

    repo = GuardRepo(ROOT)
    g0 = Guard.from_texts(*repo.files_at("gen-0"))
    gn = Guard.from_dir(ROOT / "guard")
    from piiguard.cli import _classifier
    gclf = Guard.from_dir(ROOT / "guard", _classifier(True))
    pres = presidio_redactor()
    systems = {
        "Microsoft Presidio (default)": lambda rec: pres(rec["text"]),
        "piiguard gen-0 rules": lambda rec: g0.redact(rec["text"]).text,
        "piiguard current rules": lambda rec: gn.redact(rec["text"]).text,
        "piiguard current rules + matching industry pack": lambda rec: domain_guard(gn, pack_for(rec["domain"])).redact(rec["text"]).text,
        "piiguard rules + industry pack + Nemotron classifier (routed)": lambda rec: domain_guard(gclf, pack_for(rec["domain"])).redact(rec["text"]).text,
    }
    out = {"n_records": len(records), "n_entities": sum(len(x["spans"]) for x in records), "domains": dict(Counter(x["domain"] for x in records)), "systems": {}}
    for name, fn in systems.items():
        t0 = time.time()
        with ThreadPoolExecutor(6) as ex:
            outs = list(ex.map(fn, records))
        caught = Counter(); total = Counter(); leaked_records = 0; by_domain_leak = defaultdict(lambda: [0, 0])
        for rec, red in zip(records, outs):
            truth = [s["text"] for s in rec["spans"]]
            missed = set(_missed_values(red, truth))
            if missed:
                leaked_records += 1
            by_domain_leak[rec["domain"]][0] += 1 if missed else 0
            by_domain_leak[rec["domain"]][1] += 1
            for s in rec["spans"]:
                total[s["label"]] += 1
                if s["text"] not in missed:
                    caught[s["label"]] += 1
        recall = sum(caught.values()) / max(1, sum(total.values()))
        hard_labels = [k for k in total if HARD.search(k)]
        hard_recall = sum(caught[k] for k in hard_labels) / max(1, sum(total[k] for k in hard_labels))
        out["systems"][name] = {
            "entity_recall": round(recall, 4), "hard_identifier_recall": round(hard_recall, 4), "n_hard": sum(total[k] for k in hard_labels),
            "record_leak_rate": round(leaked_records / len(records), 4),
            "ms_per_text": round(1000 * (time.time() - t0) / len(records), 1),
            "recall_by_label": {k: round(caught[k] / total[k], 3) for k, _ in total.most_common()},
            "hard_labels": sorted(hard_labels),
            "leak_rate_by_domain": {d: round(a / b, 3) for d, (a, b) in sorted(by_domain_leak.items())},
        }
        print(f"{name:<62} recall {recall:6.1%}  hard-id recall {hard_recall:6.1%}  record leak {leaked_records/len(records):6.1%}  {out['systems'][name]['ms_per_text']:>7} ms/text", file=sys.stderr)
    (ROOT / "runs").mkdir(exist_ok=True)
    (ROOT / "runs" / "external-nemotron-pii.json").write_text(json.dumps(out, indent=2))
    print(json.dumps({k: {"entity_recall": v["entity_recall"], "record_leak_rate": v["record_leak_rate"]} for k, v in out["systems"].items()}, indent=2))


if __name__ == "__main__":
    main()
