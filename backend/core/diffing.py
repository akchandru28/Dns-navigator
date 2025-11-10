from __future__ import annotations
from collections import Counter
import ipaddress
from typing import Dict, List, Tuple, Any, Optional, Set, Iterable
from .utils import rrkey, canon_answers
import dns.name

def resolver_role(resolver_id: str) -> str:
    return "authoritative" if resolver_id.lower().startswith("auth:") else "public"

def compute_consistency(cells: List[dict]) -> Dict[str, str]:
    bucket: Dict[str, Dict[str, Tuple[str, ...]]] = {}
    for c in cells:
        key = rrkey(c["name"], c["rtype"])
        bucket.setdefault(key, {})
        bucket[key][c["resolver_id"]] = tuple(canon_answers(c["answers"]))
    verdict: Dict[str, str] = {}
    for k, per_resolver in bucket.items():
        vals = list(per_resolver.values())
        verdict[k] = "CONSISTENT" if len(set(vals)) <= 1 else "DRIFT"
    return verdict

def _mode_or_min(values: List[int]) -> Optional[int]:
    if not values:
        return None
    counter = Counter(values)
    max_count = max(counter.values())
    candidates = [ttl for ttl, count in counter.items() if count == max_count]
    return min(candidates)

def parse_soa_serial(answer: str) -> Optional[int]:
    parts = answer.split()
    if len(parts) >= 3:
        try:
            return int(parts[2])
        except ValueError:
            return None
    return None

def normalize_name(name: str) -> str:
    try:
        return dns.name.from_text(name).to_text().rstrip(".").lower()
    except Exception:
        return name.lower().rstrip(".")

def canonicalize_rdata(rrtype: str, rdata: str) -> str:
    value = (rdata or "").strip()
    if not value:
        return value
    upper = (rrtype or "").upper()
    try:
        if upper == "A":
            return str(ipaddress.IPv4Address(value))
        if upper == "AAAA":
            return str(ipaddress.IPv6Address(value))
    except Exception:
        pass
    def _canon_name_token(token: str) -> str:
        try:
            return dns.name.from_text(token).to_text().rstrip(".").lower()
        except Exception:
            return token.strip().lower().rstrip(".")
    if upper in {"CNAME", "NS", "PTR"}:
        return _canon_name_token(value)
    if upper == "MX":
        parts = value.split()
        if len(parts) >= 2:
            pref = parts[0]
            target = _canon_name_token(" ".join(parts[1:]))
            return f"{pref} {target}"
    if upper == "SRV":
        parts = value.split()
        if len(parts) >= 4:
            head = " ".join(parts[:3])
            target = _canon_name_token(" ".join(parts[3:]))
            return f"{head} {target}"
    return value.strip().lower()

def build_authoritative_union(auth_answers: Iterable[Iterable[str]], rrtype: str) -> Set[str]:
    union: Set[str] = set()
    for ans in auth_answers or []:
        for record in ans or []:
            union.add(canonicalize_rdata(rrtype, record))
    return union

def _status_to_rcode(status: Optional[str]) -> str:
    mapping = {
        "OK": "NOERROR",
        "NODATA": "NODATA",
        "NXDOMAIN": "NXDOMAIN",
    }
    if status is None:
        return "ERR"
    return mapping.get(status.upper(), "ERR")

def _derive_authoritative_rcode(auth_rows: List[dict], authoritative_union: Set[str]) -> str:
    if authoritative_union:
        return "NOERROR"
    rcodes = [_status_to_rcode(row.get("status")) for row in auth_rows if row.get("status")]
    if not rcodes:
        return "ERR"
    if "NOERROR" in rcodes:
        return "NOERROR"
    if all(rc == "NXDOMAIN" for rc in rcodes):
        return "NXDOMAIN"
    if all(rc == "NODATA" for rc in rcodes):
        return "NODATA"
    return "ERR"

def _cname_shape_ok(rrtype: str, answers: List[str]) -> bool:
    if rrtype.upper() != "CNAME":
        return True
    filtered = [a for a in answers if a]
    return len(filtered) <= 1

def classify_resolver_answer_against_union(
    resolver_answers: Iterable[str],
    authoritative_union: Set[str],
    rrtype: str,
    resolver_rcode: str,
    authoritative_rcode: str,
    cname_shape_ok: bool,
) -> Tuple[str, str]:
    resolver_rcode = (resolver_rcode or "ERR").upper()
    authoritative_rcode = (authoritative_rcode or "ERR").upper()
    if not cname_shape_ok:
        return "FAIL", "CNAME_SHAPE"
    if resolver_rcode not in {"NOERROR", "NODATA", "NXDOMAIN"}:
        return "FAIL", "RCODE"

    res_set: Set[str] = set(canonicalize_rdata(rrtype, r) for r in (resolver_answers or []))
    auth_positive = bool(authoritative_union)

    if authoritative_rcode == "NOERROR" and auth_positive and resolver_rcode == "NXDOMAIN":
        return "FAIL", "NXDOMAIN_CONFLICT"
    if authoritative_rcode in {"NXDOMAIN", "NODATA"}:
        if res_set:
            return "FAIL", "POSITIVE_VS_NEGATIVE"
        return "PASS", "NEGATIVE_AGREEMENT"

    if resolver_rcode == "NXDOMAIN":
        return ("FAIL", "NXDOMAIN_CONFLICT") if auth_positive else ("PASS", "BOTH_NEGATIVE")
    if resolver_rcode == "NODATA":
        return ("WARN", "NODATA_VS_POSITIVE") if auth_positive else ("PASS", "NEGATIVE_AGREEMENT")

    if not res_set:
        return ("WARN", "EMPTY_VS_POSITIVE") if auth_positive else ("PASS", "BOTH_EMPTY")

    if not authoritative_union:
        return "WARN", "NO_AUTH"

    if res_set.issubset(authoritative_union):
        return ("PASS", "MATCH") if res_set == authoritative_union else ("WARN", "SUBSET")
    return "FAIL", "SET_MISMATCH"

def _resolvers_agree(public_sets: Set[Tuple[str,...]], public_statuses: Set[str]) -> bool:
    return (len([s for s in public_sets if s]) <= 1) and (len([s for s in public_statuses if s]) <= 1)

def analyze_rrsets(
    cells: List[dict],
    ttl_threshold: int = 300,
    auth_union: Optional[Dict[str, List[str]]] = None,
    auth_union_sets: Optional[Dict[str, Set[Tuple[str,...]]]] = None,
    auth_union_ttls: Optional[Dict[str, Optional[int]]] = None,
    feature_auth_union: bool = False,
    policy: Optional[Dict[str, Any]] = None
):
    per_rr: Dict[str, Dict[str, Any]] = {}
    for c in cells:
        key = rrkey(c["name"], c["rtype"])
        info = per_rr.setdefault(key, {
            "auth_sets": set(),
            "public_sets": set(),
            "auth_ttls": [],
            "rows": []
        })
        role = resolver_role(c["resolver_id"])
        answers = canon_answers(c.get("answers", []))
        tup = tuple(answers)
        if role == "authoritative":
            info["auth_sets"].add(tup)
            if c.get("ttl") is not None:
                info["auth_ttls"].append(c["ttl"])
        else:
            info["public_sets"].add(tup)
        info["rows"].append({
            "resolver_id": c["resolver_id"],
            "role": role,
            "answers": answers,
            "name": c["name"],
            "rtype": c["rtype"],
            "server": c["resolver_id"].split("@")[-1],
            "ttl": c.get("ttl"),
            "status": c.get("status")
        })

    per_rr_verdict: Dict[str, str] = {}
    consistency: Dict[str, str] = {}
    weak_ttl_keys: Set[str] = set()
    variance_note: Optional[str] = None
    variance_explainer: Optional[str] = None
    auth_ttl_by_rr: Dict[str, Optional[int]] = {}
    diff_rows: List[Dict[str, Any]] = []
    warn_present = False
    fail_present = False
    union_miss_present = False
    contradiction_present = False
    soa_ns_stable_flag = True
    auth_union = auth_union or {}
    auth_union_sets = auth_union_sets or {}
    auth_union_ttls = auth_union_ttls or {}
    auth_union_sizes: Dict[str, int] = {k: len(v) for k, v in auth_union.items()}
    auth_union_by_rr: Dict[str, List[str]] = {k: list(v) for k, v in auth_union.items()}
    policy = policy or {}
    policy_min_ttl = {k.upper(): v for k, v in policy.get("min_ttl", {}).items()}
    warn_labels = policy.get("warn_labels", {})
    warn_ttl_enabled = warn_labels.get("weak_ttl", True)
    warn_cdn_enabled = warn_labels.get("cdn_variance", True)
    drift_conf = policy.get("drift", {})
    tolerant_mode = bool(drift_conf.get("tolerant_mode", False))
    effective_warn_cdn = warn_cdn_enabled or tolerant_mode
    rr_type_by_rr: Dict[str, str] = {}
    records: List[Dict[str, Any]] = []

    for key, info in per_rr.items():
        rr_type = info["rows"][0]["rtype"] if info["rows"] else ""
        rr_type_by_rr[key] = rr_type
        auth_sets = info["auth_sets"]
        verdict = "PASS"
        has_feature_union = feature_auth_union and key in auth_union
        union_sources: List[Iterable[str]] = []
        union_answer_sets = auth_union_sets.get(key) if has_feature_union else None
        if has_feature_union:
            union_sources.append(auth_union.get(key, []))
        else:
            union_sources.extend(list(auth_sets))
        canonical_union = build_authoritative_union(union_sources, rr_type)
        if not has_feature_union and key not in auth_union_by_rr:
            fallback_union = sorted({ans for tup in auth_sets for ans in tup})
            if fallback_union:
                auth_union_by_rr[key] = fallback_union
                auth_union_sizes[key] = len(fallback_union)

        auth_rows = [row for row in info["rows"] if row["role"] == "authoritative"]
        authoritative_rcode = _derive_authoritative_rcode(auth_rows, canonical_union)
        public_statuses = {row.get("status") or "ERR" for row in info["rows"] if row["role"] == "public"}
        resolvers_agree = _resolvers_agree(info["public_sets"], public_statuses)
        per_row_grades: Dict[str, str] = {}
        per_row_reasons: Dict[str, str] = {}
        row_union_flags: Dict[str, bool] = {}
        row_contra_flags: Dict[str, bool] = {}
        variance_flag = False
        auth_union_present = bool(canonical_union)
        rr_union_miss = False
        rr_contradiction = False

        if not auth_union_present:
            for row in info["rows"]:
                grade = "PASS" if row["role"] == "authoritative" else "WARN"
                per_row_grades[row["resolver_id"]] = grade
            verdict = "WARN"
            consistency_label = "UNKNOWN"
            warn_present = True
        else:
            consistency_label = "CONSISTENT"
            for row in info["rows"]:
                if row["role"] != "public":
                    per_row_grades[row["resolver_id"]] = "PASS"
                    per_row_reasons[row["resolver_id"]] = "AUTH"
                    row_union_flags[row["resolver_id"]] = False
                    row_contra_flags[row["resolver_id"]] = False
                    continue
                resolver_rcode = _status_to_rcode(row.get("status"))
                cname_ok = _cname_shape_ok(rr_type, row["answers"])
                grade, reason = classify_resolver_answer_against_union(
                    row["answers"],
                    canonical_union,
                    rr_type,
                    resolver_rcode,
                    authoritative_rcode,
                    cname_ok,
                    )
                per_row_reasons[row["resolver_id"]] = reason
                is_union_miss = reason == "SET_MISMATCH"
                row_union_flags[row["resolver_id"]] = is_union_miss
                row_contra = reason in {"NXDOMAIN_CONFLICT","POSITIVE_VS_NEGATIVE","CNAME_SHAPE","RCODE","NODATA_VS_POSITIVE","EMPTY_VS_POSITIVE"}
                row_contra_flags[row["resolver_id"]] = row_contra
                if is_union_miss:
                    rr_union_miss = True
                    union_miss_present = True
                if row_contra:
                    rr_contradiction = True
                    contradiction_present = True
                if grade == "FAIL" and is_union_miss and soa_ns_stable_flag and not row_contra:
                    grade = "WARN"
                if grade == "WARN" and not effective_warn_cdn:
                    grade = "PASS"
                per_row_grades[row["resolver_id"]] = grade
            if any(g == "FAIL" for g in per_row_grades.values()):
                verdict = "FAIL"
                consistency_label = "DRIFT"
            elif any(g == "WARN" for g in per_row_grades.values()):
                verdict = "WARN"
                consistency_label = "VARIANCE" if variance_flag else "DRIFT"
            else:
                verdict = "PASS"
                consistency_label = "CONSISTENT"

        if not auth_union_present:
            consistency_label = "UNKNOWN"

        auth_ttl = auth_union_ttls.get(key)
        if auth_ttl is None:
            auth_ttl = _mode_or_min(info["auth_ttls"])
        auth_ttl_by_rr[key] = auth_ttl
        ttl_limit = policy_min_ttl.get(rr_type.upper(), ttl_threshold)
        if warn_ttl_enabled and auth_ttl is not None and ttl_limit is not None and auth_ttl < ttl_limit and verdict != "FAIL":
            verdict = "WARN"
            weak_ttl_keys.add(key)

        if key.endswith(" SOA"):
            auth_serials: List[int] = []
            source_sets = union_answer_sets if union_answer_sets else auth_sets
            for tup in source_sets or []:
                iterable = [tup] if not isinstance(tup, tuple) else [tup]
                for entry in iterable:
                    if isinstance(entry, tuple):
                        for ans in entry:
                            serial = parse_soa_serial(ans)
                            if serial is not None:
                                auth_serials.append(serial)
                    else:
                        serial = parse_soa_serial(entry)
                        if serial is not None:
                            auth_serials.append(serial)
            auth_serials = list({s for s in auth_serials})
            if len(auth_serials) > 1:
                verdict = "FAIL"
                soa_ns_stable_flag = False
            elif auth_serials:
                auth_serial = auth_serials[0]
                for row in info["rows"]:
                    if row["role"] != "public":
                        continue
                    answers = row["answers"]
                    if not answers:
                        continue
                    row_serial = parse_soa_serial(answers[0])
                    if row_serial is None or row_serial >= auth_serial:
                        continue
                    ttl = row.get("ttl") or 0
                    if ttl > 0:
                        continue
                        verdict = "FAIL"
                        soa_ns_stable_flag = False
                    break

        per_rr_verdict[key] = verdict
        consistency[key] = consistency_label
        if verdict == "WARN":
            warn_present = True
        if verdict == "FAIL":
            fail_present = True

        for row in info["rows"]:
            grade = per_row_grades.get(row["resolver_id"], "PASS")
            matches = grade != "FAIL"
            row_union = row_union_flags.get(row["resolver_id"], False)
            row_contra = row_contra_flags.get(row["resolver_id"], False)
            row_issue = None
            if row["role"] == "public":
                if not auth_union_present:
                    row_issue = "No authoritative data captured for this RRset; comparison is advisory."
                elif row_contra:
                    row_issue = "Resolver result contradicts authoritative data (mismatch cannot be explained by CDN)."
                elif row_union and soa_ns_stable_flag:
                    row_issue = "CDN variance: public answer outside authoritative union, but NS/SOA stable and no contradictions."
            diff_rows.append({
                "rr_key": key,
                "resolver_id": row["resolver_id"],
                "answers": row["answers"],
                "role": row["role"],
                "matches_authoritative": bool(matches),
                "dig_cmd": f"dig +norecurse @{row['server']} {row['name']} {row['rtype']}",
                "issue": row_issue,
                "flags": {
                    "union_miss": row_union,
                    "no_contradictions": not row_contra,
                    "soa_ns_stable": soa_ns_stable_flag,
                    "resolvers_consistent": resolvers_agree,
                }
            })

        qname, qtype = key.split(" ", 1)
        records.append({
            "qname": qname,
            "qtype": qtype.upper(),
            "verdict": verdict,
            "consistency": consistency_label,
            "auth_union_present": auth_union_present,
            "authoritative_union": sorted(canonical_union),
            "resolver_answers": [
                {
                    "resolver_id": row["resolver_id"],
                    "role": row["role"],
                    "status": row.get("status"),
                    "answers": row["answers"],
                    "issue": (
                        "No authoritative data captured for this RRset; comparison is advisory."
                        if (row["role"] == "public" and not auth_union_present)
                        else (
                            "Resolver result contradicts authoritative data (mismatch cannot be explained by CDN)."
                            if (row["role"] == "public" and row_contra_flags.get(row["resolver_id"], False))
                            else (
                                "CDN variance: public answer outside authoritative union, but NS/SOA stable and no contradictions."
                                if (row["role"] == "public" and row_union_flags.get(row["resolver_id"], False) and soa_ns_stable_flag)
                                else None
                            )
                        )
                    ),
                    "flags": {
                        "union_miss": row_union_flags.get(row["resolver_id"], False),
                        "no_contradictions": not row_contra_flags.get(row["resolver_id"], False),
                        "soa_ns_stable": soa_ns_stable_flag,
                        "resolvers_consistent": resolvers_agree,
                    },
                }
                for row in info["rows"]
            ],
            "flags": {
                "union_miss": rr_union_miss,
                "no_contradictions": not rr_contradiction,
                "soa_ns_stable": soa_ns_stable_flag,
                "resolvers_consistent": resolvers_agree,
            }
        })

    if fail_present:
        variance_note = "One or more public answers don't match any authoritative response."
        variance_explainer = variance_note
    elif warn_present:
        variance_note = "Variance across public resolvers is common for large CDNs. Confirm authoritatives agree."
        variance_explainer = variance_note

    weak_ttl = sorted(weak_ttl_keys)
    filtered_rows = [row for row in diff_rows if per_rr_verdict.get(row["rr_key"]) != "PASS"]
    filtered_rows.sort(key=lambda r: (r["rr_key"], r["role"], r["resolver_id"]))

    return {
        "per_rr_verdict": per_rr_verdict,
        "consistency": consistency,
        "weak_ttl": weak_ttl,
        "auth_ttl_by_rr": auth_ttl_by_rr,
        "variance_note": variance_note,
        "variance_explainer": variance_explainer,
        "diff_rows": filtered_rows,
        "auth_union_size_by_rr": auth_union_sizes,
        "auth_union_by_rr": auth_union_by_rr,
        "auth_union_present": bool(auth_union_by_rr),
        "rr_type_by_rr": rr_type_by_rr,
        "records": records,
        "flags": {
            "union_miss": union_miss_present,
            "no_contradictions": not contradiction_present,
            "soa_ns_stable": soa_ns_stable_flag
        }
    }

def snapshot_union(cells: List[dict]) -> Dict[str, List[str]]:
    snap: Dict[str, set] = {}
    for c in cells:
        key = rrkey(c["name"], c["rtype"])
        snap.setdefault(key, set()).update(c["answers"])
    return {k: sorted(v) for k, v in snap.items()}

def diff_snapshots(prev: Dict[str, List[str]], cur: Dict[str, List[str]]):
    added, removed, modified = {}, {}, {}
    prev_keys, cur_keys = set(prev.keys()), set(cur.keys())
    for k in sorted(cur_keys - prev_keys):
        added[k] = cur[k]
    for k in sorted(prev_keys - cur_keys):
        removed[k] = prev[k]
    for k in sorted(prev_keys & cur_keys):
        if prev[k] != cur[k]:
            modified[k] = {"from": prev[k], "to": cur[k]}
    return added, removed, modified

DEFAULT_TYPE_WEIGHTS = {
    "A": 2,
    "AAAA": 2,
    "SOA": 2,
    "MX": 1,
    "TXT": 1,
    "NS": 1
}
SCORE_VALUES = {"PASS": 0, "WARN": 1, "FAIL": 4}

def drift_score_from_verdicts(verdicts: Dict[str,str], rr_types: Dict[str,str], weights: Optional[Dict[str,int]] = None) -> int:
    weights_map = DEFAULT_TYPE_WEIGHTS.copy()
    if weights:
        weights_map.update({k.upper(): v for k, v in weights.items()})
    total_weight = 0
    weighted_score = 0
    for key, verdict in verdicts.items():
        rtype = rr_types.get(key, "").upper()
        weight = weights_map.get(rtype, 1)
        weighted_score += weight * SCORE_VALUES.get(verdict, 0)
        total_weight += weight * SCORE_VALUES["FAIL"]
    if total_weight == 0:
        return 0
    return int(round((weighted_score / total_weight) * 100))
