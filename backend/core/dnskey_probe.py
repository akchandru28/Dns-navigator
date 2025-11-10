from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import List, Optional, Literal, Tuple

import dns.asyncquery
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

Transport = Literal["udp", "tcp"]

EDNS_PAYLOAD = 1232
JITTER_RANGE = (0.01, 0.05)
DNSKEY_RT = dns.rdatatype.DNSKEY


@dataclass
class ProbeBreadcrumb:
    ns_ip: str
    transport: Transport
    edns: bool
    edns_bufsize: Optional[int]
    do: bool
    rcode: str
    tc: bool
    flags: List[str]
    elapsed_ms: int
    attempt_no: int
    exception: Optional[str] = None


@dataclass
class DNSKeyProbeResult:
    ok: bool
    dnskey_rrset: Optional[dns.rrset.RRset]
    rrsig_rrset: Optional[dns.rrset.RRset]
    used_ns_ip: Optional[str]
    breadcrumbs: List[ProbeBreadcrumb] = field(default_factory=list)
    error: Optional[str] = None


def _canonicalize_zone(zone: str) -> str:
    z = (zone or "").strip().lower()
    if not z:
        raise ValueError("zone must be non-empty")
    if not z.endswith("."):
        z += "."
    return z


def _rcode_text(resp: Optional[dns.message.Message], err: Optional[str]) -> str:
    if resp is not None:
        return dns.rcode.to_text(resp.rcode())
    if err:
        err_lower = err.lower()
        if "timeout" in err_lower:
            return "TIMEOUT"
        if "formerr" in err_lower:
            return "FORMERR"
        return err.split(":")[0].upper()
    return "NO_RESPONSE"


def _collect_flags(resp: Optional[dns.message.Message]) -> List[str]:
    if not resp:
        return []
    mapping = (
        (dns.flags.AA, "aa"),
        (dns.flags.AD, "ad"),
        (dns.flags.QR, "qr"),
        (dns.flags.RA, "ra"),
    )
    return [name for bit, name in mapping if resp.flags & bit]


def _has_dnskey_bundle(resp: Optional[dns.message.Message]) -> Tuple[Optional[dns.rrset.RRset], Optional[dns.rrset.RRset]]:
    if not resp:
        return None, None
    dnskey_rrset = None
    rrsig_rrset = None
    for rrset in resp.answer:
        if rrset.rdtype == DNSKEY_RT:
            dnskey_rrset = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG:
            try:
                iterable = getattr(rrset, "items", rrset)
                for rdata in iterable:
                    covered = getattr(rdata, "type_covered", getattr(rdata, "covered", None))
                    if covered == DNSKEY_RT:
                        rrsig_rrset = rrset
                        break
            except Exception:
                pass
    return dnskey_rrset, rrsig_rrset


def _is_timeout_error(err: Optional[str]) -> bool:
    if not err:
        return False
    return "timed out" in err.lower()


async def _send_query(
    zone: str,
    ns_ip: str,
    transport: Transport,
    use_edns: bool,
    timeout_sec: float,
) -> Tuple[Optional[dns.message.Message], Optional[str], float]:
    q = dns.message.make_query(zone, DNSKEY_RT, want_dnssec=True)
    if use_edns:
        q.use_edns(edns=0, payload=EDNS_PAYLOAD, ednsflags=dns.flags.DO)
    else:
        q.use_edns(False)
    q.flags &= ~dns.flags.RD
    start = time.perf_counter()
    try:
        if transport == "tcp":
            resp = await dns.asyncquery.tcp(q, ns_ip, timeout=timeout_sec)
        else:
            resp = await dns.asyncquery.udp(q, ns_ip, timeout=timeout_sec)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return resp, None, elapsed_ms
    except Exception as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return None, str(exc), elapsed_ms


async def fetch_dnskey_with_fallback(
    zone: str,
    ns_ips: List[str],
    timeout_connect_ms: int,
    timeout_read_ms: int,
    retries: int = 1,
) -> DNSKeyProbeResult:
    canonical_zone = _canonicalize_zone(zone)
    unique_ips = sorted({ip.strip() for ip in ns_ips if ip and ip.strip()})
    if not unique_ips:
        return DNSKeyProbeResult(
            ok=False,
            dnskey_rrset=None,
            rrsig_rrset=None,
            used_ns_ip=None,
            breadcrumbs=[],
            error="No authoritative nameserver IPs provided.",
        )

    total_timeout_ms = max(timeout_connect_ms + timeout_read_ms, 100)
    timeout_sec = total_timeout_ms / 1000.0
    max_attempts_per_step = max(1, retries + 1)

    start_index = random.randrange(len(unique_ips))
    rotated = unique_ips[start_index:] + unique_ips[:start_index]

    breadcrumbs: List[ProbeBreadcrumb] = []
    attempt_no = 0
    last_error: Optional[str] = None

    async def query_step(ns_ip: str, transport: Transport, use_edns: bool) -> Tuple[Optional[dns.message.Message], Optional[str], bool]:
        nonlocal attempt_no, last_error
        final_resp: Optional[dns.message.Message] = None
        final_err: Optional[str] = None
        for _ in range(max_attempts_per_step):
            attempt_no += 1
            resp, err, elapsed = await _send_query(canonical_zone, ns_ip, transport, use_edns, timeout_sec)
            final_resp = resp or final_resp
            final_err = err
            breadcrumb = ProbeBreadcrumb(
                ns_ip=ns_ip,
                transport=transport,
                edns=use_edns,
                edns_bufsize=EDNS_PAYLOAD if use_edns else None,
                do=use_edns,
                rcode=_rcode_text(resp, err),
                tc=bool(resp and resp.flags & dns.flags.TC),
                flags=_collect_flags(resp),
                elapsed_ms=int(round(elapsed)),
                attempt_no=attempt_no,
                exception=err,
            )
            breadcrumbs.append(breadcrumb)
            if resp is not None:
                return resp, None, True
            if err and not _is_timeout_error(err):
                break
        if final_resp is not None:
            return final_resp, None, True
        last_error = final_err or "query failed"
        return None, final_err, False

    for ns_ip in rotated:
        await asyncio.sleep(random.uniform(*JITTER_RANGE))
        # Step 1: UDP + EDNS
        resp, err, _ = await query_step(ns_ip, "udp", True)
        dnskey_rrset, rrsig_rrset = _has_dnskey_bundle(resp)
        if resp and resp.rcode() == dns.rcode.SERVFAIL:
            last_error = f"{ns_ip} returned SERVFAIL over UDP/EDNS."
            continue
        if dnskey_rrset and rrsig_rrset and resp and resp.rcode() == dns.rcode.NOERROR:
            return DNSKeyProbeResult(True, dnskey_rrset, rrsig_rrset, ns_ip, breadcrumbs, None)

        resp_formerr = resp and resp.rcode() == dns.rcode.FORMERR
        need_tcp_edns = (not dnskey_rrset) or (not rrsig_rrset)

        # Step 2: TCP + EDNS
        resp2 = None
        if need_tcp_edns and not resp_formerr:
            resp2, err2, _ = await query_step(ns_ip, "tcp", True)
            dnskey_rrset, rrsig_rrset = _has_dnskey_bundle(resp2)
            if resp2 and resp2.rcode() == dns.rcode.SERVFAIL:
                last_error = f"{ns_ip} returned SERVFAIL over TCP/EDNS."
                continue
            if dnskey_rrset and rrsig_rrset and resp2 and resp2.rcode() == dns.rcode.NOERROR:
                return DNSKeyProbeResult(True, dnskey_rrset, rrsig_rrset, ns_ip, breadcrumbs, None)
            resp_formerr = resp2 and resp2.rcode() == dns.rcode.FORMERR
            err = err2
        else:
            resp2 = resp

        # Step 3: UDP without EDNS (only if EDNS caused FORMERR)
        resp3 = None
        if resp_formerr:
            resp3, err3, _ = await query_step(ns_ip, "udp", False)
            dnskey_rrset, rrsig_rrset = _has_dnskey_bundle(resp3)
            if resp3 and resp3.rcode() == dns.rcode.SERVFAIL:
                last_error = f"{ns_ip} returned SERVFAIL over UDP/no-EDNS."
                continue
            if dnskey_rrset and rrsig_rrset and resp3 and resp3.rcode() == dns.rcode.NOERROR:
                return DNSKeyProbeResult(True, dnskey_rrset, rrsig_rrset, ns_ip, breadcrumbs, None)

            # Step 4: TCP without EDNS
            resp4, _, _ = await query_step(ns_ip, "tcp", False)
            dnskey_rrset, rrsig_rrset = _has_dnskey_bundle(resp4)
            if resp4 and resp4.rcode() == dns.rcode.SERVFAIL:
                last_error = f"{ns_ip} returned SERVFAIL over TCP/no-EDNS."
                continue
            if dnskey_rrset and rrsig_rrset and resp4 and resp4.rcode() == dns.rcode.NOERROR:
                return DNSKeyProbeResult(True, dnskey_rrset, rrsig_rrset, ns_ip, breadcrumbs, None)

        last_error = last_error or "DNSKEY retrieval failed for this nameserver."

    return DNSKeyProbeResult(
        ok=False,
        dnskey_rrset=None,
        rrsig_rrset=None,
        used_ns_ip=None,
        breadcrumbs=breadcrumbs,
        error=last_error or "All authoritative nameservers failed to return DNSKEY.",
    )


async def _demo() -> None:
    ips = [
        "173.245.58.51",   # ns1.cloudflare.com
        "173.245.59.41",   # ns2.cloudflare.com
        "198.41.222.162",  # ns3.cloudflare.com
    ]
    result = await fetch_dnskey_with_fallback("cloudflare.com.", ips, 500, 1500, retries=1)
    summary = f"ok={result.ok} ns={result.used_ns_ip} attempts={len(result.breadcrumbs)}"
    print(summary)
    if result.breadcrumbs:
        print(f"last breadcrumb: {result.breadcrumbs[-1]}")


if __name__ == "__main__":
    asyncio.run(_demo())
