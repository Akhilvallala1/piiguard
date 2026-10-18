"""Turn NVIDIA's Nemotron-PII test split into a red-team pack: structured-identifier spans become surface_forms.
Stratified by domain, fixed seeds, disjoint from the 290-record external evaluation sample. Output: data/attacks-nemotron/."""
from __future__ import annotations

import ast, json, re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
HARD = re.compile(r"ssn|social|card|routing|account|iban|passport|licen|customer_id|employee_id|member|mrn|medical|npi|policy|claim|phone|email|ip_address|mac_address|vin|date_of_birth|dob|tax|ein|swift|bic|api_key|password|username|user_id|device|imei|plate|cvv|pin\b|bank", re.I)


def take(df, n, seed, exclude):
    parts = [g.sample(min(len(g), max(1, n // df["domain"].nunique() + 1)), random_state=seed) for _, g in df.groupby("domain")]
    s = pd.concat(parts).sample(frac=1, random_state=seed)
    s = s[~s["uid"].isin(exclude)].head(n)
    out = []
    for _, r in s.iterrows():
        spans = ast.literal_eval(r["spans"]) if isinstance(r["spans"], str) else list(r["spans"])
        sfs = [str(sp["text"]) for sp in spans if sp.get("text") not in (None, "") and HARD.search(str(sp["label"]))]
        sfs = [x for x in sfs if x in r["text"]]
        if sfs:
            out.append({"id": f"npii-{r['uid'][:8]}", "technique": "nemotron", "pii_type": "structured", "carrier": r["domain"], "text": r["text"], "surface_forms": sfs})
    return out


def main():
    df = pd.read_parquet(ROOT / "data/external/nemotron-pii/test.parquet")
    df = df[df["locale"] == "us"]
    used = set()
    train = take(df, 220, 101, used); used |= {x["id"][5:] for x in train}
    val = take(df, 70, 202, used); used |= {x["id"][5:] for x in val}
    heldout = take(df, 120, 303, used)
    out = ROOT / "data/attacks-nemotron"; out.mkdir(exist_ok=True)
    for name, rows in (("train", train), ("val", val), ("heldout", heldout)):
        with (out / f"{name}.jsonl").open("w") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print({k: len(v) for k, v in (("train", train), ("val", val), ("heldout", heldout))})


if __name__ == "__main__":
    main()
