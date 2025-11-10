from __future__ import annotations
import time
from typing import Any, Dict, List, Optional, Tuple, Set
import dns.dnssec, dns.name, dns.rdatatype, dns.rcode
from .dns_probe import _query, get_authoritative_ns_ips
from .dnskey_probe import fetch_dnskey_with_fallback, ProbeBreadcrumb
from .schemas import DNSSECLintResult

NEGATIVE_PROBE_SUFFIX = "_nonexist"
CONNECT_TIMEOUT_MS = 800
READ_TIMEOUT_MS = 2500

_ALLOWED_DIGEST_MAP = {
    1: "SHA1",
    2: "SHA256",
    4: "SHA384",
}

def _canon_owner(zone: str) -> str:
    z = (zone or "").strip().rstrip(".").lower()
    return z + "."

def _split_dnskeys_by_role(dnskey_rrset) -> Tuple[List[Any], List[Any]]:
    ksks: List[Any] = []
    zsks: List[Any] = []
    if not dnskey_rrset:
        return ksks, zsks
    for rdata in dnskey_rrset:
        flags = int(getattr(rdata, "flags", 0))
        is_zone = bool(flags & 0x0100)
        is_sep = bool(flags & 0x0001)
        if is_zone and is_sep:
            ksks.append(rdata)
        elif is_zone:
            zsks.append(rdata)
    return ksks, zsks

def _parent_digest_types(parent_ds_rrset) -> Set[int]:
    types: Set[int] = set()
    if not parent_ds_rrset:
        return types
    for ds in parent_ds_rrset:
        dt = getattr(ds, "digest_type", None)
        if dt in _ALLOWED_DIGEST_MAP:
            types.add(dt)
    return types

def _ds_matches_any_ksk(zone: str, parent_ds_rrset, child_dnskey_rrset, strict_alg: bool) -> Tuple[bool, bool, Optional[str]]:
    zone_name = dns.name.from_text(_canon_owner(zone))
    ksks, _ = _split_dnskeys_by_role(child_dnskey_rrset)
    if not ksks or not parent_ds_rrset:
        return False, False, None
    digest_types = _parent_digest_types(parent_ds_rrset)
    if not digest_types:
        digest_types = {2}
    alg_blocked = False
    ds_error: Optional[str] = None
    for ds in parent_ds_rrset:
        dt = getattr(ds, "digest_type", None)
        if dt not in digest_types:
            continue
        algo_name = _ALLOWED_DIGEST_MAP.get(dt)
        if not algo_name:
            continue
        for key in ksks:
            if strict_alg and getattr(ds, "algorithm", None) != getattr(key, "algorithm", None):
                alg_blocked = True
                continue
            try:
                cand = dns.dnssec.make_ds(zone_name, key, algo_name)
            except Exception as e:
                ds_error = f"DS generation error: {e}"
                continue
            if (
                getattr(ds, "key_tag", None) == getattr(cand, "key_tag", None)
                and getattr(ds, "digest_type", None) == getattr(cand, "digest_type", None)
                and getattr(ds, "digest", None) == getattr(cand, "digest", None)
            ):
                return True, alg_blocked, None
    return False, alg_blocked, ds_error

def _dnskey_rrsig_valid_now(rrsig_rrset, now: Optional[int] = None, skew_s: int = 300) -> bool:
    if not rrsig_rrset:
        return False
    now = now or int(time.time())
    for rrsig in rrsig_rrset:
        inc = int(getattr(rrsig, "inception", 0))
        exp = int(getattr(rrsig, "expiration", 0))
        if inc - skew_s <= now <= exp + skew_s:
            return True
    return False

async def _fetch_parent_ds(domain: str, timeout: float):
    labels = dns.name.from_text(domain)
    parent = labels.parent()
    parent_name = "." if parent == dns.name.root else parent.to_text().rstrip(".")
    parent_ns = await get_authoritative_ns_ips(parent_name) if parent_name else []
    targets = parent_ns or [("recursor", "8.8.8.8")]
    for (_ns, ip) in targets:
        rd = ip == "8.8.8.8"
        resp, err = await _query(ip, domain, "DS", do=False, rd=rd, timeout=timeout)
        if err or not resp:
            continue
        for rrset in (resp.answer or []):
            if rrset.rdtype == dns.rdatatype.DS:
                return rrset
    return None

async def _collect_authoritative_ips(domain: str, auth_ns_ips: List[Tuple[str, str]]):
    ips = [ip for _ns, ip in auth_ns_ips]
    if ips:
        return ips
    resolved = await get_authoritative_ns_ips(domain)
    return [ip for _ns, ip in resolved]


def _serialize_breadcrumbs(entries: List[ProbeBreadcrumb]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for entry in entries:
        output.append({
            "ns_ip": entry.ns_ip,
            "transport": entry.transport,
            "edns": entry.edns,
            "edns_bufsize": entry.edns_bufsize,
            "do": entry.do,
            "rcode": entry.rcode,
            "tc": entry.tc,
            "flags": entry.flags,
            "elapsed_ms": entry.elapsed_ms,
            "attempt_no": entry.attempt_no,
            "exception": entry.exception
        })
    return output

async def lint_dnssec(domain: str, auth_ns_ips: List[Tuple[str,str]], do: bool,
                      strict_alg: bool, expiry_thresh_h: int, timeout: float) -> DNSSECLintResult:
    res = DNSSECLintResult(
        ds_present=False, ds_match=False, dnskey_rrsig_valid=False,
        rrsig_expiry_hours=None, nsec_present=None, issues=[],
        state="UNSIGNED", summary="PASS", probe_log=[]
    )
    ds_rrset = await _fetch_parent_ds(domain, timeout)
    res.ds_present = ds_rrset is not None

    ns_ips = await _collect_authoritative_ips(domain, auth_ns_ips)
    probe_result = await fetch_dnskey_with_fallback(
        domain if domain.endswith(".") else f"{domain}.",
        ns_ips,
        timeout_connect_ms=CONNECT_TIMEOUT_MS,
        timeout_read_ms=READ_TIMEOUT_MS,
        retries=1
    )
    res.probe_log = _serialize_breadcrumbs(probe_result.breadcrumbs)
    key_source = probe_result.used_ns_ip
    dnskey_rrset = probe_result.dnskey_rrset
    rrsig_rrset = probe_result.rrsig_rrset
    issues: List[str] = []
    expiry_hours: Optional[float] = None

    has_bundle = bool(dnskey_rrset and rrsig_rrset)
    rrsig_window_valid = _dnskey_rrsig_valid_now(rrsig_rrset)

    if has_bundle:
        name = dns.name.from_text(domain)
        if not name.is_absolute():
            name = name.concatenate(dns.name.root)
        name = name.canonicalize()
        try:
            dns.dnssec.validate(dnskey_rrset, rrsig_rrset, {name: dnskey_rrset})
            res.dnskey_rrsig_valid = True
        except Exception as e:
            issues.append(f"DNSKEY RRSIG validation failed: {e}")

        if ds_rrset:
            try:
                match, alg_blocked, ds_error = _ds_matches_any_ksk(domain, ds_rrset, dnskey_rrset, strict_alg)
                res.ds_match = match
                if ds_error:
                    issues.append(ds_error)
                if not match:
                    if strict_alg and alg_blocked:
                        issues.append("Algorithm not permitted by strict policy.")
                    else:
                        issues.append("Parent DS does not match any child KSK DNSKEY.")
            except Exception as e:
                issues.append(f"DS/DNSKEY comparison error: {e}")

        try:
            soonest = min([r.expiration for r in rrsig_rrset])
            now = int(time.time())
            expiry_hours = (soonest - now) / 3600.0
            res.rrsig_expiry_hours = expiry_hours
            if expiry_hours < 0:
                issues.append("RRSIG already expired.")
            elif expiry_hours < float(expiry_thresh_h):
                issues.append(f"RRSIG expires in {expiry_hours:.1f}h (< {expiry_thresh_h}h).")
        except Exception:
            pass
    else:
        if res.ds_present:
            issues.append(probe_result.error or "DNSKEY/RRSIG(DNSKEY) not retrievable from authoritative servers.")

    try:
        bogus = f"{NEGATIVE_PROBE_SUFFIX}-{int(time.time())}.{domain}"
        query_target = key_source or "8.8.8.8"
        rd_flag = query_target == "8.8.8.8"
        nxd, _ = await _query(query_target, bogus, "A", do=True, rd=rd_flag, timeout=timeout)
        nsec = False
        if nxd:
            for rrset in (nxd.authority or []):
                if rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
                    nsec = True
                    break
        res.nsec_present = nsec
    except Exception:
        res.nsec_present = None

    if not res.ds_present:
        res.state = "UNSIGNED"
        res.summary = "PASS"
        res.issues = []
        return res

    expiry_ok = (expiry_hours is None) or (expiry_hours >= float(expiry_thresh_h))

    if has_bundle and res.dnskey_rrsig_valid and rrsig_window_valid and res.ds_match and expiry_ok:
        res.state = "SIGNED_VALID"
        res.summary = "PASS"
        if res.nsec_present is False:
            issues.append("Advisory: negative proof (NSEC/NSEC3) not observed in synthetic NXDOMAIN probe.")
        res.issues = issues
    elif not has_bundle:
        res.state = "INDETERMINATE"
        res.summary = "WARN"
        issues.append("DNSKEY retrieval failed at all authoritative nameservers; see probe log.")
        res.issues = issues
    else:
        res.state = "SIGNED_BROKEN"
        res.summary = "FAIL"
        reasons = []
        if not res.ds_match:
            reasons.append("Parent DS does not match any child KSK DNSKEY.")
        if not res.dnskey_rrsig_valid or not rrsig_window_valid:
            reasons.append("DNSKEY RRset signature invalid or outside validity window.")
        if not expiry_ok and expiry_hours is not None:
            reasons.append(f"RRSIG(DNSKEY) expires in {expiry_hours:.1f}h (< {expiry_thresh_h}h).")
        if reasons:
            issues.extend(reasons)
        elif not issues:
            issues.append("Signed but broken: Parent DS does not match child DNSKEY or DNSKEY/RRSIG missing.")
        res.issues = issues
    return res
