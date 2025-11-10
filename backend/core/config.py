from __future__ import annotations
import os, json, copy
from typing import Dict, Any

DEFAULT_POLICY = {
    "min_ttl": {
        "A": 300,
        "AAAA": 300,
        "MX": 600,
        "TXT": 300,
        "NS": 86400,
        "SOA": 300
    },
    "weights": {
        "A": 2,
        "AAAA": 2,
        "SOA": 2,
        "MX": 1,
        "TXT": 1,
        "NS": 1
    },
    "warn_labels": {
        "weak_ttl": True,
        "cdn_variance": True
    },
    "drift": {
        "tolerant_mode": True
    }
}

_POLICY_CACHE: Dict[str, Any] | None = None

def _load_json(path: str) -> Dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        return None
    return None

def _parse_env_json(env_name: str) -> Dict[str, Any] | None:
    raw = os.getenv(env_name)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except Exception:
        return None
    return None

def _normalize_keys(source: Dict[str, Any]) -> Dict[str, Any]:
    return {str(k).upper(): v for k, v in source.items()}

def get_policy() -> Dict[str, Any]:
    global _POLICY_CACHE
    if _POLICY_CACHE is not None:
        return _POLICY_CACHE

    policy = copy.deepcopy(DEFAULT_POLICY)

    file_path = os.getenv("DNS_POLICY_FILE")
    if file_path and os.path.exists(file_path):
        data = _load_json(file_path)
        if data:
            policy.update(data)
    env_json = _parse_env_json("DNS_POLICY_JSON")
    if env_json:
        policy.update(env_json)

    min_ttl_env = _parse_env_json("DNS_POLICY_MIN_TTL")
    if min_ttl_env:
        policy["min_ttl"] = min_ttl_env
    weights_env = _parse_env_json("DNS_POLICY_WEIGHTS")
    if weights_env:
        policy["weights"] = weights_env
    warn_env = _parse_env_json("DNS_POLICY_WARN_LABELS")
    if warn_env:
        policy["warn_labels"] = warn_env

    policy["min_ttl"] = _normalize_keys(policy.get("min_ttl", {}))
    policy["weights"] = _normalize_keys(policy.get("weights", {}))
    warn_labels = policy.get("warn_labels", {})
    policy["warn_labels"] = {k: bool(v) for k, v in warn_labels.items()}
    drift_conf = policy.get("drift", {})
    if not isinstance(drift_conf, dict):
        drift_conf = {}
    drift_env = _parse_env_json("DNS_POLICY_DRIFT")
    if drift_env:
        drift_conf.update(drift_env)
    policy["drift"] = {
        "tolerant_mode": bool(drift_conf.get("tolerant_mode", False))
    }

    _POLICY_CACHE = policy
    return policy
