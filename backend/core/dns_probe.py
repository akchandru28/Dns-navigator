from __future__ import annotations
import asyncio, random, time
from typing import Dict, List, Tuple, Optional, Set, Any
import dns.message, dns.rdatatype, dns.flags, dns.name, dns.rcode
import dns.asyncquery, dns.query, dns.zone
from .utils import rrkey, canon_answers

RECURSIVE_DEFAULT = "8.8.8.8"

async def _query(server_ip: str, name: str, rtype: str,
                 do: bool = True, rd: bool = True, timeout: float = 4.0,
                 transport: str = "udp", edns_payload: Optional[int] = 1232,
                 honor_tc: bool = False):
    q = dns.message.make_query(name, rtype, want_dnssec=do)
    if edns_payload:
        q.use_edns(edns=0, payload=edns_payload)
    else:
        q.use_edns(False)
    if not rd:
        q.flags &= ~dns.flags.RD
    try:
        if transport == "tcp":
            resp = await dns.asyncquery.tcp(q, server_ip, timeout=timeout)
        else:
            resp = await dns.asyncquery.udp(q, server_ip, timeout=timeout)
            if (resp.flags & dns.flags.TC) and not honor_tc:
                resp = await dns.asyncquery.tcp(q, server_ip, timeout=timeout)
        return resp, None
    except Exception as e:
        return None, str(e)

def _extract_answers(resp, rtype: str) -> Tuple[List[str], Optional[int], str, int]:
    if resp is None:
        return [], None, "ERR", dns.rcode.NOERROR
    # Look for answer rrset of target type (or NODATA/NXDOMAIN)
    status = "OK"
    ttl = None
    answers: List[str] = []
    rt = dns.rdatatype.from_text(rtype)
    rcode = resp.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        return [], None, "NXDOMAIN", rcode
    if rcode != dns.rcode.NOERROR:
        return [], None, "ERR", rcode
    # answer rrset for the type?
    got_type = False
    for rrset in resp.answer:
        if rrset.rdtype == rt:
            got_type = True
            ttl = rrset.ttl
            for r in rrset:
                answers.append(r.to_text())
    if not got_type:
        # Could be NODATA or referral
        status = "NODATA"
    return canon_answers(answers), ttl, status, rcode

async def resolve_rrset(server_ip: str, name: str, rtype: str, do: bool, rd: bool, timeout: float):
    ladder = [
        ("udp", 1232),
        ("udp", 0),
        ("tcp", 1232),
        ("tcp", 0)
    ]
    tried = []
    retries = 0
    for transport, payload in ladder:
        start = time.perf_counter()
        resp, err = await _query(server_ip, name, rtype, do=do, rd=rd, timeout=timeout,
                                 transport=transport, edns_payload=payload if payload else None)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        tried.append({
            "transport": transport,
            "edns": payload if payload else 0,
            "error": err is not None,
            "elapsed_ms": round(elapsed_ms, 2)
        })
        if err:
            retries += 1
            continue
        answers, ttl, status, rcode = _extract_answers(resp, rtype)
        fallback_used = any(a["error"] for a in tried[:-1])
        return {
            "answers": answers,
            "ttl": ttl,
            "status": status,
            "error": None,
            "raw": resp,
            "path": {
                "transport": transport,
                "edns": payload if payload else 0,
                "rcode": rcode,
                "rcode_name": dns.rcode.to_text(rcode),
                "flags": int(resp.flags),
                "retries": retries,
                "attempts": tried,
                "elapsed_ms": round(elapsed_ms, 2),
                "fallback_used": fallback_used
            }
        }
    fallback_used = any(a["error"] for a in tried[:-1])
    return {
        "answers": [],
        "ttl": None,
        "status": "ERR",
        "error": "All transports failed",
        "path": {
            "attempts": tried,
            "fallback_used": fallback_used,
            "retries": retries
        }
    }

def _axfr_sync(zone_name: str, ip: str, timeout: float):
    xfr = dns.query.xfr(where=ip, zone=zone_name, timeout=timeout, relativize=False)
    return dns.zone.from_xfr(xfr, relativize=False)

async def attempt_axfrs(domain: str, auth_ns: List[Tuple[str,str]], timeout: float):
    if not auth_ns:
        return {"union": {}, "answer_sets": {}, "ttl": {}, "results": []}
    semaphore = asyncio.Semaphore(2)
    union: Dict[str, Set[str]] = {}
    answer_sets: Dict[str, Set[Tuple[str,...]]] = {}
    ttl_map: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    async def worker(ns_name: str, ip: str):
        async with semaphore:
            rr_count = 0
            try:
                zone = await asyncio.to_thread(_axfr_sync, domain, ip, timeout)
                origin = zone.origin
                for name, node in zone.nodes.items():
                    fqdn = name.derelativize(origin).to_text().rstrip(".")
                    for rdataset in node.rdatasets:
                        rrtype = dns.rdatatype.to_text(rdataset.rdtype)
                        answers = [rdata.to_text() for rdata in rdataset]
                        if not answers:
                            continue
                        key = rrkey(fqdn, rrtype)
                        union.setdefault(key, set()).update(answers)
                        answer_sets.setdefault(key, set()).add(tuple(sorted(answers)))
                        ttl = rdataset.ttl
                        if ttl is not None:
                            ttl_map[key] = min(ttl, ttl_map.get(key, ttl))
                        rr_count += 1
                results.append({
                    "ns_name": ns_name,
                    "ip": ip,
                    "success": True,
                    "error": None,
                    "rrset_count": rr_count
                })
            except Exception as e:
                results.append({
                    "ns_name": ns_name,
                    "ip": ip,
                    "success": False,
                    "error": str(e),
                    "rrset_count": 0
                })

    await asyncio.gather(*[worker(ns, ip) for ns, ip in auth_ns])
    return {
        "union": {k: set(v) for k, v in union.items()},
        "answer_sets": answer_sets,
        "ttl": ttl_map,
        "results": results
    }

async def get_authoritative_ns_ips(domain: str, recursive_ip: str = RECURSIVE_DEFAULT,
                                   timeout: float = 4.0) -> List[Tuple[str,str]]:
    # Ask a recursive resolver for NS, then resolve A/AAAA for those NS names
    ns_resp, err = await _query(recursive_ip, domain, "NS", do=False, rd=True, timeout=timeout)
    if err or ns_resp is None:
        return []
    ns_names = []
    for rrset in (ns_resp.answer or []):
        if rrset.rdtype == dns.rdatatype.NS:
            for r in rrset:
                ns_names.append(str(r.target).rstrip('.'))
    # Fallback: sometimes NS is in authority section (delegation)
    if not ns_names:
        for rrset in (ns_resp.authority or []):
            if rrset.rdtype == dns.rdatatype.NS:
                for r in rrset:
                    ns_names.append(str(r.target).rstrip('.'))

    ns_ips: List[Tuple[str,str]] = []
    for ns in sorted(set(ns_names)):
        for typ in ("A","AAAA"):
            a_resp, _ = await _query(recursive_ip, ns, typ, do=False, rd=True, timeout=timeout)
            if a_resp:
                for rrset in a_resp.answer:
                    if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                        for r in rrset:
                            ns_ips.append((ns, r.address))
    # Deduplicate
    seen = set()
    uniq: List[Tuple[str,str]] = []
    for ns, ip in ns_ips:
        k = (ns, ip)
        if k not in seen:
            uniq.append(k); seen.add(k)
    return uniq

async def run_multi_resolver(domain: str, resolvers: List[str], record_types: List[str],
                             do: bool, timeout: float, max_qps: float) -> Tuple[List[dict], List[str], List[Tuple[str,str]]]:
    """
    Returns:
      - cells: list of RRsetCell-like dicts per resolver×rtype
      - errors: top-level errors
      - auth_ns: list of authoritative (ns, ip) pairs actually used (if "authoritative" requested)
    """
    errors: List[str] = []
    rate = max(0.0, 1.0/max_qps) if max_qps > 0 else 0.0
    semaphore = asyncio.Semaphore(int(max(1, max_qps)))  # coarse control

    # Expand "authoritative" keyword into specific NS IPs
    auth_ns: List[Tuple[str,str]] = []
    expanded_resolvers: List[Tuple[str,bool]] = []  # (resolver_id, rd)
    for r in resolvers:
        if r.lower().startswith("authoritative"):
            if not auth_ns:
                auth_ns = await get_authoritative_ns_ips(domain)
            for (ns, ip) in auth_ns:
                expanded_resolvers.append((f"auth:{ns}@{ip}", False))  # RD=0
        else:
            expanded_resolvers.append((r, True))  # RD=1 (recursive)
    if not expanded_resolvers:
        errors.append("No resolvers available.")

    async def worker(resolver_id: str, rd: bool, rtype: str):
        await asyncio.sleep(rate*random.random())  # jitter
        server_ip = resolver_id.split("@")[-1] if resolver_id.startswith("auth:") else resolver_id
        res = await resolve_rrset(server_ip, domain, rtype, do=do, rd=rd, timeout=timeout)
        return {
            "name": domain, "rtype": rtype, "resolver_id": resolver_id,
            "ttl": res.get("ttl"), "answers": res.get("answers", []),
            "status": res.get("status"), "error": res.get("error"),
            "diagnostics": res.get("path")
        }

    tasks = []
    for (rid, rd) in expanded_resolvers:
        for rtype in record_types:
            tasks.append(worker(rid, rd, rtype))

    cells: List[dict] = []
    # throttle with semaphore
    async def sem_task(coro):
        async with semaphore:
            return await coro

    results = await asyncio.gather(*[sem_task(t) for t in tasks], return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            errors.append(str(r))
        else:
            cells.append(r)

    return cells, errors, auth_ns

async def sample_authoritative_union(domain: str, record_types: List[str],
                                      auth_ns: List[Tuple[str,str]], attempts: int = 2,
                                      jitter_range: Tuple[float,float] = (0.05, 0.15),
                                      timeout: float = 4.0) -> Dict[str, Dict[str, object]]:
    if not auth_ns:
        return {"union": {}, "ttl": {}, "answer_sets": {}}
    semaphore = asyncio.Semaphore(10)
    async def query(ns_name: str, ip: str, rtype: str, attempt: int):
        await asyncio.sleep(random.uniform(*jitter_range))
        async with semaphore:
            res = await resolve_rrset(ip, domain, rtype, do=True, rd=False, timeout=timeout)
        return ns_name, rtype, res

    tasks = []
    for ns_name, ip in auth_ns:
        for rtype in record_types:
            for attempt in range(attempts):
                tasks.append(query(ns_name, ip, rtype, attempt))

    union: Dict[str, set] = {}
    ttl_map: Dict[str, Optional[int]] = {}
    answer_sets: Dict[str, set] = {}
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for item in results:
        if isinstance(item, Exception):
            continue
        ns_name, rtype, res = item
        key = rrkey(domain, rtype)
        if res["status"] != "OK":
            continue
        answers = canon_answers(res.get("answers", []))
        if not answers:
            continue
        union.setdefault(key, set()).update(answers)
        ttl = res.get("ttl")
        if ttl is not None:
            ttl_map[key] = min(ttl, ttl_map.get(key, ttl))
        answer_sets.setdefault(key, set()).add(tuple(answers))
    return {
        "union": {k: sorted(v) for k, v in union.items()},
        "ttl": ttl_map,
        "answer_sets": answer_sets
    }
