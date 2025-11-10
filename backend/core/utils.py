from __future__ import annotations
from typing import Iterable, List
import time
import hashlib

def now() -> float:
    return time.time()

def rrkey(name: str, rtype: str) -> str:
    return f"{name.lower()} {rtype.upper()}"

def canon_answers(ans: Iterable[str]) -> List[str]:
    return sorted(set([a.strip() for a in ans]))
    
def hash_snapshot(snapshot: dict) -> str:
    m = hashlib.sha256()
    for k in sorted(snapshot.keys()):
        m.update(k.encode())
        for v in snapshot[k]:
            m.update(v.encode())
    return m.hexdigest()
