from __future__ import annotations
import os, json, glob, time
from typing import Dict, Any, Optional, List, Tuple

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

def run_paths(run_id: str) -> Tuple[str,str]:
    base = os.path.join(DATA_DIR, f"{run_id}")
    return base + ".json", base + ".csv"

def save_run_json(run_id: str, payload: dict) -> str:
    p, _ = run_paths(run_id)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return p

def save_run_csv(run_id: str, csv_bytes: bytes) -> str:
    _, p = run_paths(run_id)
    with open(p, "wb") as f:
        f.write(csv_bytes)
    return p

def list_runs(domain: Optional[str] = None) -> List[dict]:
    items = []
    for path in sorted(glob.glob(os.path.join(DATA_DIR, "*.json")), reverse=True):
        try:
            with open(path, "r", encoding="utf-8") as f:
                j = json.load(f)
                if (domain is None) or (j.get("options", {}).get("domain") == domain):
                    items.append({
                        "run_id": j.get("run_id"),
                        "domain": j.get("options", {}).get("domain"),
                        "phase": j.get("phase"),
                        "progress": j.get("progress"),
                        "started_at": j.get("summary",{}).get("started_at") or j.get("meta",{}).get("started_at"),
                        "duration_sec": j.get("summary",{}).get("duration_sec"),
                    })
        except Exception:
            continue
    return items

def load_run(run_id: str) -> Optional[dict]:
    p, _ = run_paths(run_id)
    if not os.path.exists(p): return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)
