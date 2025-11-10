from __future__ import annotations
from typing import List, Dict, Optional, Literal, Any
from pydantic import BaseModel, Field

Phase = Literal["Idle","Queued","Probing","Validating","Analyzing","Reporting","Completed","Error"]

DEFAULT_RESOLVERS = ["1.1.1.1","8.8.8.8","9.9.9.9","authoritative"]

class DNSSECOptions(BaseModel):
    do: bool = True
    strict_alg_match: bool = False
    expiry_threshold_hours: int = 48

class RateLimits(BaseModel):
    max_qps: float = 20.0
    timeout_sec: float = 4.0
    retries: int = 1

class RunOptions(BaseModel):
    domain: str
    resolvers: List[str] = Field(default_factory=lambda: DEFAULT_RESOLVERS.copy())
    record_types: List[str] = Field(default_factory=lambda: ["A","AAAA","CNAME","MX","TXT","NS","SOA"])
    dnssec: DNSSECOptions = DNSSECOptions()
    rate_limits: RateLimits = RateLimits()
    enable_axfr: bool = False
    axfr_timeout_sec: float = 8.0

class RRsetCell(BaseModel):
    name: str
    rtype: str
    resolver_id: str
    ttl: Optional[int] = None
    answers: List[str] = Field(default_factory=list)
    status: Literal["OK","NXDOMAIN","NODATA","ERR"] = "OK"
    error: Optional[str] = None
    diagnostics: Optional[Dict[str, Any]] = None

class RecordsOverview(BaseModel):
    grid: List[RRsetCell]
    consistency: Dict[str, Literal["CONSISTENT","DRIFT","VARIANCE","UNKNOWN"]] = {}
    weak_ttl: List[str] = Field(default_factory=list)
    per_rr_verdict: Dict[str, Literal["PASS","WARN","FAIL"]] = Field(default_factory=dict)
    variance_note: Optional[str] = None
    auth_ttl_by_rr: Dict[str, Optional[int]] = Field(default_factory=dict)
    auth_union_present: bool = False
    auth_union_by_rr: Dict[str, List[str]] = Field(default_factory=dict)
    auth_union_size_by_rr: Dict[str, int] = Field(default_factory=dict)
    nxdomain_hotspots: List["NXDomainHotspot"] = Field(default_factory=list)

class DNSSECLintResult(BaseModel):
    ds_present: bool
    ds_match: bool
    dnskey_rrsig_valid: bool
    rrsig_expiry_hours: Optional[float] = None
    nsec_present: Optional[bool] = None
    issues: List[str] = Field(default_factory=list)
    state: Literal["SIGNED_VALID","SIGNED_BROKEN","UNSIGNED","INDETERMINATE"] = "UNSIGNED"
    summary: Literal["PASS","WARN","FAIL"] = "PASS"
    probe_log: List[Dict[str, Any]] = Field(default_factory=list)

class DiffRow(BaseModel):
    rr_key: str
    resolver_id: str
    role: Literal["public","authoritative"]
    answers: List[str] = Field(default_factory=list)
    matches_authoritative: bool = True
    dig_cmd: str

class DriftAcrossRuns(BaseModel):
    score: int
    added: Dict[str, List[str]] = Field(default_factory=dict)
    removed: Dict[str, List[str]] = Field(default_factory=dict)
    modified: Dict[str, Dict[str, List[str]]] = Field(default_factory=dict)  # rr -> {from,to}
    diff_rows: List[DiffRow] = Field(default_factory=list)

class NameserverHealthItem(BaseModel):
    ns_name: str
    ip: str
    family: Literal["IPv4","IPv6"]
    health_score: float
    latency_ms_p95: float
    error_rate: float
    fallback_used: bool

class NameserverHealth(BaseModel):
    ns: List[NameserverHealthItem] = Field(default_factory=list)

class NXDomainHotspot(BaseModel):
    label: str
    rtype: str
    resolver_id: str
    count: int
    last_rcode: str
    last_seen_ts: float

class RunSummary(BaseModel):
    pass_count: int = 0
    warn_count: int = 0
    fail_count: int = 0
    started_at: float
    duration_sec: float
    resolver_count: int
    records_scanned: int

class AXFRResult(BaseModel):
    ns_name: str
    ip: str
    success: bool
    error: Optional[str] = None
    rrset_count: int = 0

class RunResult(BaseModel):
    run_id: str
    options: RunOptions
    phase: Phase
    progress: int
    meta: Dict[str, Any] = {}
    overview: Optional[RecordsOverview] = None
    dnssec: Optional[DNSSECLintResult] = None
    drift: Optional[DriftAcrossRuns] = None
    ns_health: Optional[NameserverHealth] = None
    axfr_results: List[AXFRResult] = Field(default_factory=list)
    summary: Optional[RunSummary] = None
    errors: List[str] = Field(default_factory=list)
    schema_version: Optional[str] = None
    generator: Optional[str] = None
    run: Optional[Dict[str, Any]] = None
