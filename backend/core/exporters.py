from __future__ import annotations
import os, json
import pandas as pd
from typing import List, Dict

def write_json(path: str, payload: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

def write_csv(path: str, cells: List[dict]):
    # Flatten to tabular
    rows = []
    for c in cells:
        answers = sorted(c.get("answers", []))
        rows.append({
            "name": c["name"],
            "type": c["rtype"],
            "resolver": c["resolver_id"],
            "ttl": c.get("ttl"),
            "status": c.get("status"),
            "answers": "; ".join(answers),
            "error": c.get("error"),
        })
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False)
