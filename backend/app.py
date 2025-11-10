from __future__ import annotations
import asyncio, os, json, time, uuid, math
from typing import Dict, Any, List, Optional, Iterable, Tuple
from dataclasses import dataclass
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.schemas import RunOptions, RunResult, RecordsOverview, RunSummary
from core.schemas import DNSSECLintResult, DriftAcrossRuns, NameserverHealth, NameserverHealthItem
from core.dns_probe import run_multi_resolver, sample_authoritative_union, get_authoritative_ns_ips, attempt_axfrs
from core.dnssec import lint_dnssec
from core.diffing import compute_consistency, analyze_rrsets, snapshot_union, diff_snapshots, drift_score_from_verdicts
from core.exporters import write_json, write_csv
from core.storage import save_run_json, list_runs, load_run, run_paths
from core.utils import now
from core.config import get_policy

load_dotenv()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://dnsnavigator-frjwabci2-chandrus-projects-4341ac9b.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
RUNS: Dict[str, dict] = {}  # in-memory live runs

@dataclass
class RunVerdictPolicy:
    dnssec_chain_error_as_fail: bool = False

def _dnssec_weight_for_run(state: str, *, fail_broken_in_free_tier: bool = False) -> str:
    if state == "SIGNED_VALID":
        return "PASS"
    if state == "UNSIGNED":
        return "PASS"
    if state == "INDETERMINATE":
        return "WARN"
    if state == "SIGNED_BROKEN":
        return "FAIL" if not fail_broken_in_free_tier else "WARN"
    return "FAIL"

def map_run_verdict(
    rrset_grades: Iterable[str],
    dnssec_state: str,
    policy: RunVerdictPolicy,
    *,
    union_miss_for_some_rr: bool = False,
    soa_ns_stable: Optional[bool] = None,
    no_contradictions: Optional[bool] = None,
) -> Tuple[str, List[str]]:
    issues: List[str] = []
    grade_list = list(rrset_grades or [])
    rr_weight = "PASS"
    if any(g == "FAIL" for g in grade_list):
        rr_weight = "FAIL"
    elif any(g == "WARN" for g in grade_list):
        rr_weight = "WARN"

    if (
        rr_weight == "FAIL"
        and union_miss_for_some_rr
        and soa_ns_stable is True
        and no_contradictions is True
        and not policy.dnssec_chain_error_as_fail
    ):
        rr_weight = "WARN"
        issues.append("Public answers outside authoritative union without contradictions; treating as CDN variance.")

    dnssec_weight = _dnssec_weight_for_run(dnssec_state, fail_broken_in_free_tier=policy.dnssec_chain_error_as_fail)

    weights = [dnssec_weight, rr_weight]
    if "FAIL" in weights:
        return "FAIL", issues
    if "WARN" in weights:
        return "WARN", issues
    return "PASS", issues

@app.get("/api/resolvers")
def default_resolvers():
    return ["1.1.1.1","8.8.8.8","9.9.9.9","authoritative"]

@app.post("/api/run")
async def create_run(opts: RunOptions):
    run_id = str(uuid.uuid4())[:8]
    start_t = now()
    RUNS[run_id] = {
        "result": {
            "run_id": run_id, "options": json.loads(opts.model_dump_json()),
            "phase": "Queued", "progress": 0, "meta": {"started_at": start_t},
            "overview": None, "dnssec": None, "drift": None, "ns_health": None,
            "summary": None, "errors": []
        },
        "started": start_t,
        "done": False,
    }
    asyncio.create_task(_execute_run(run_id))
    return {"run_id": run_id, "phase": "Queued"}

@app.get("/api/run/{run_id}")
def get_run(run_id: str):
    live = RUNS.get(run_id)
    if live:
        return live["result"]
    persisted = load_run(run_id)
    if not persisted:
        raise HTTPException(404, "Run not found")
    return persisted

@app.get("/api/runs")
def get_runs(domain: Optional[str] = None):
    return list_runs(domain)

@app.get("/api/export/{run_id}/json")
def export_json(run_id: str):
    persisted = load_run(run_id)
    if not persisted:
        raise HTTPException(404, "Run not found")
    path, _ = run_paths(run_id)
    return FileResponse(path, media_type="application/json", filename=f"dns-navigator-{run_id}.json")

@app.get("/api/export/{run_id}/csv")
def export_csv(run_id: str):
    persisted = load_run(run_id)
    if not persisted:
        raise HTTPException(404, "Run not found")
    _, path = run_paths(run_id)
    return FileResponse(path, media_type="text/csv", filename=f"dns-navigator-{run_id}.csv")

async def _execute_run(run_id: str):
    r = RUNS[run_id]["result"]
    opts = RunOptions(**r["options"])
    policy = get_policy()
    feature_flags = {"auth_union": True}
    def percentile(values: List[float], perc: float) -> float:
        if not values:
            return 0.0
        values = sorted(values)
        if len(values) == 1:
            return values[0]
        k = (len(values) - 1) * perc
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return values[f]
        return values[f] + (values[c] - values[f]) * (k - f)

    def update(phase: str, progress: int):
        r["phase"] = phase; r["progress"] = progress

    try:
        update("Probing", 10)
        cells, errors, auth_ns = await run_multi_resolver(
            opts.domain, opts.resolvers, opts.record_types,
            do=opts.dnssec.do, timeout=opts.rate_limits.timeout_sec,
            max_qps=opts.rate_limits.max_qps
        )
        cells.sort(key=lambda c: (c["resolver_id"], c["name"], c["rtype"]))
        r["errors"].extend(errors)

        def build_nxdomain_hotspots(cells: List[dict]) -> List[Dict[str, Any]]:
            now_ts = now()
            stats: Dict[Tuple[str,str,str], Dict[str, Any]] = {}
            for cell in cells:
                status = cell.get("status")
                diag = cell.get("diagnostics") or {}
                rcode_name = diag.get("rcode_name") or ""
                normalized = None
                if status == "NXDOMAIN":
                    normalized = "NXDOMAIN"
                elif status == "NODATA":
                    normalized = "NODATA"
                elif rcode_name == "SERVFAIL":
                    normalized = "SERVFAIL"
                if not normalized:
                    continue
                key = (cell["name"], cell["rtype"].upper(), cell["resolver_id"])
                entry = stats.get(key)
                if not entry:
                    entry = {
                        "label": cell["name"],
                        "rtype": cell["rtype"].upper(),
                        "resolver_id": cell["resolver_id"],
                        "count": 0,
                        "last_rcode": normalized,
                        "last_seen_ts": now_ts
                    }
                    stats[key] = entry
                entry["count"] += 1
                entry["last_rcode"] = normalized
                entry["last_seen_ts"] = now_ts
            return sorted(stats.values(), key=lambda x: (-x["count"], x["label"]))

        def build_ns_health(cells: List[dict]) -> List[NameserverHealthItem]:
            stats: Dict[Tuple[str,str], Dict[str, Any]] = {}
            for cell in cells:
                rid = cell.get("resolver_id", "")
                if not rid.startswith("auth:"):
                    continue
                try:
                    rest = rid.split("auth:")[1]
                    ns_name, ip = rest.split("@", 1)
                except ValueError:
                    continue
                key = (ns_name, ip)
                entry = stats.setdefault(key, {
                    "total": 0,
                    "errors": 0,
                    "fallbacks": 0,
                    "latencies": []
                })
                entry["total"] += 1
                diag = cell.get("diagnostics") or {}
                attempts = diag.get("attempts") or []
                fallback_used = diag.get("fallback_used")
                if fallback_used is None:
                    fallback_used = len(attempts) > 1 and any(a.get("error") for a in attempts[:-1])
                if fallback_used:
                    entry["fallbacks"] += 1
                status = cell.get("status")
                if status == "ERR":
                    entry["errors"] += 1
                    continue
                latency = diag.get("elapsed_ms")
                if latency is None and attempts:
                    latency = attempts[-1].get("elapsed_ms")
                if latency is not None:
                    entry["latencies"].append(float(latency))
            items: List[NameserverHealthItem] = []
            for (ns_name, ip), data in stats.items():
                total = max(1, data["total"])
                error_rate = data["errors"] / total
                fallback_rate = data["fallbacks"] / total
                p95 = percentile(data["latencies"], 0.95) if data["latencies"] else 0.0
                error_penalty = min(50.0, error_rate * 100.0)
                fallback_penalty = min(20.0, fallback_rate * 100.0)
                latency_penalty = 0.0
                if p95 > 200:
                    latency_penalty = min(30.0, (p95 - 200.0) / 5.0)
                health = max(0.0, 100.0 - error_penalty - fallback_penalty - latency_penalty)
                family = "IPv6" if ":" in ip else "IPv4"
                items.append(NameserverHealthItem(
                    ns_name=ns_name,
                    ip=ip,
                    family=family,
                    health_score=round(health, 1),
                    latency_ms_p95=round(p95, 1),
                    error_rate=round(error_rate, 3),
                    fallback_used=data["fallbacks"] > 0
                ))
            return sorted(items, key=lambda x: x.health_score, reverse=True)

        update("Validating", 40)
        dnssec = await lint_dnssec(
            opts.domain, auth_ns, do=opts.dnssec.do,
            strict_alg=opts.dnssec.strict_alg_match,
            expiry_thresh_h=opts.dnssec.expiry_threshold_hours,
            timeout=opts.rate_limits.timeout_sec
        )

        update("Analyzing", 70)
        if feature_flags["auth_union"] and not auth_ns:
            auth_ns = await get_authoritative_ns_ips(opts.domain)
        auth_union_data = {"union": {}, "answer_sets": {}, "ttl": {}}
        if feature_flags["auth_union"] and auth_ns:
            auth_union_data = await sample_authoritative_union(
                opts.domain,
                opts.record_types,
                auth_ns,
                attempts=2,
                jitter_range=(0.05,0.15),
                timeout=opts.rate_limits.timeout_sec
            )
        axfr_results = []
        if opts.enable_axfr and auth_ns:
            axfr_data = await attempt_axfrs(opts.domain, auth_ns, opts.axfr_timeout_sec)
            axfr_results = axfr_data["results"]
            for key, values in axfr_data["union"].items():
                existing = set(auth_union_data["union"].get(key, []))
                merged = existing.union(values)
                auth_union_data["union"][key] = sorted(merged)
            for key, ttl in axfr_data["ttl"].items():
                current_ttl = auth_union_data["ttl"].get(key)
                auth_union_data["ttl"][key] = ttl if current_ttl is None else min(current_ttl, ttl)
            for key, tuples in axfr_data["answer_sets"].items():
                answer_set = auth_union_data["answer_sets"].setdefault(key, set())
                answer_set.update(tuples)
        else:
            axfr_results = []
        consistency = compute_consistency(cells)
        nxdomain_hotspots = build_nxdomain_hotspots(cells)
        ns_health_items = build_ns_health(cells)

        analysis = analyze_rrsets(
            cells,
            ttl_threshold=300,
            auth_union=auth_union_data["union"] if auth_union_data else None,
            auth_union_sets=auth_union_data["answer_sets"] if auth_union_data else None,
            auth_union_ttls=auth_union_data["ttl"] if auth_union_data else None,
            feature_auth_union=feature_flags["auth_union"],
            policy=policy
        )
        overview = RecordsOverview(
            grid=cells,
            consistency=analysis["consistency"],
            weak_ttl=analysis["weak_ttl"],
            per_rr_verdict=analysis["per_rr_verdict"],
            variance_note=analysis["variance_note"],
            auth_ttl_by_rr=analysis["auth_ttl_by_rr"],
            auth_union_present=analysis["auth_union_present"],
            auth_union_by_rr=analysis["auth_union_by_rr"],
            auth_union_size_by_rr=analysis["auth_union_size_by_rr"],
            nxdomain_hotspots=nxdomain_hotspots
        )
        per_rr_verdict = analysis["per_rr_verdict"]
        rr_types = analysis["rr_type_by_rr"]
        weak_ttl = analysis["weak_ttl"]

        # Drift across runs (history)
        cur_snap = snapshot_union(cells)
        # Locate last run for this domain (excluding this run)
        history = [h for h in list_runs(opts.domain) if h["run_id"] != run_id]
        prev_snap = {}
        if history:
            prev = load_run(history[0]["run_id"])
            if prev and "overview" in prev and prev["overview"]:
                prev_snap = prev["overview"]["grid"]  # raw cells
                # re-create union from raw cells
                from core.diffing import snapshot_union as _su
                prev_snap = _su(prev["overview"]["grid"])
        added, removed, modified = diff_snapshots(prev_snap or {}, cur_snap or {})
        drift_score = drift_score_from_verdicts(per_rr_verdict, rr_types, policy.get("weights"))
        drift = DriftAcrossRuns(
            score=drift_score,
            added=added,
            removed=removed,
            modified=modified,
            diff_rows=analysis["diff_rows"]
        )

        update("Reporting", 85)
        pass_rr = sum(1 for v in per_rr_verdict.values() if v == "PASS")
        warn_rr = sum(1 for v in per_rr_verdict.values() if v == "WARN")
        fail_rr = sum(1 for v in per_rr_verdict.values() if v == "FAIL")
        pass_c = pass_rr
        warn_c = warn_rr
        fail_c = fail_rr

        verdict_policy = RunVerdictPolicy(
            dnssec_chain_error_as_fail=policy.get("dnssec_fail_is_fail", False)
        )
        flags = analysis.get("flags", {})
        run_verdict, verdict_issues = map_run_verdict(
            per_rr_verdict.values(),
            dnssec.state,
            verdict_policy,
            union_miss_for_some_rr=flags.get("union_miss", False),
            soa_ns_stable=flags.get("soa_ns_stable"),
            no_contradictions=flags.get("no_contradictions"),
        )

        if dnssec.state == "SIGNED_BROKEN":
            if verdict_policy.dnssec_chain_error_as_fail:
                fail_c += 1
            else:
                warn_c += 1
        elif dnssec.state == "INDETERMINATE":
            warn_c += 1
        else:
            pass_c += 1

        duration = now() - RUNS[run_id]["started"]
        summary = RunSummary(
            pass_count=pass_c, warn_count=warn_c, fail_count=fail_c,
            started_at=RUNS[run_id]["started"], duration_sec=duration,
            resolver_count=len(set([c["resolver_id"] for c in cells])),
            records_scanned=len(cells)
        )

        r["overview"] = json.loads(overview.model_dump_json())
        r["dnssec"] = json.loads(dnssec.model_dump_json())
        r["drift"] = json.loads(drift.model_dump_json())
        summary_dict = summary.model_dump()
        summary_dict["run_verdict"] = run_verdict
        summary_dict["issues"] = verdict_issues
        r["summary"] = summary_dict
        r["records"] = analysis.get("records", [])
        r["meta"]["auth_ns"] = auth_ns
        if analysis["variance_explainer"]:
            r["meta"]["variance_explainer"] = analysis["variance_explainer"]
        r["meta"]["run_verdict"] = run_verdict
        if verdict_issues:
            r["meta"]["run_verdict_notes"] = verdict_issues

        axfr_summary = None
        if axfr_results:
            success_count = sum(1 for res in axfr_results if res["success"])
            record_count = sum(res["rrset_count"] for res in axfr_results if res["success"])
            errors = [res["error"] for res in axfr_results if not res["success"] and res.get("error")]
            axfr_summary = {
                "attempted": len(axfr_results),
                "success_count": success_count,
                "record_count": record_count,
                "errors": errors[:3]
            }
        r["meta"]["axfr_summary"] = axfr_summary
        r["axfr_results"] = axfr_results

        ns_health_model = NameserverHealth(ns=ns_health_items)
        r["ns_health"] = json.loads(ns_health_model.model_dump_json())

        timestamp_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        r["schema_version"] = "1.3"
        r["generator"] = "dns-navigator"
        r["run"] = {
            "domain": opts.domain,
            "timestamp_utc": timestamp_utc,
            "resolvers": opts.resolvers,
            "record_types": opts.record_types,
            "dnssec": {"do": opts.dnssec.do, "strict_alg": opts.dnssec.strict_alg_match},
            "timeouts": {"connect_ms": 500, "read_ms": 1500},
            "retries": opts.rate_limits.retries,
            "feature": {"auth_union": feature_flags["auth_union"]},
            "policy": policy,
            "axfr": {"enabled": opts.enable_axfr, "timeout_sec": opts.axfr_timeout_sec}
        }

        # Persist artifacts
        base_json, base_csv = run_paths(run_id)
        write_json(base_json, r)
        write_csv(base_csv, cells)

        update("Completed", 100)
        RUNS[run_id]["done"] = True
    except Exception as e:
        r["phase"] = "Error"
        r["errors"].append(str(e))
        # persist error snapshot
        base_json, base_csv = run_paths(run_id)
        write_json(base_json, r)
