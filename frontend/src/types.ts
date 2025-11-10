export type Phase = "Idle"|"Queued"|"Probing"|"Validating"|"Analyzing"|"Reporting"|"Completed"|"Error";

export interface DNSSECOptions {
  do: boolean;
  strict_alg_match: boolean;
  expiry_threshold_hours: number;
}
export interface RateLimits {
  max_qps: number;
  timeout_sec: number;
  retries: number;
}
export interface RunOptions {
  domain: string;
  resolvers: string[];
  record_types: string[];
  dnssec: DNSSECOptions;
  rate_limits: RateLimits;
  enable_axfr: boolean;
  axfr_timeout_sec: number;
}
export interface LocationInfo {
  city?: string;
  country?: string;
  countryCode?: string;
  flag?: string;
}

export interface RRsetCell {
  name: string;
  rtype: string;
  resolver_id: string;
  ttl?: number;
  answers: string[];
  status: "OK"|"NXDOMAIN"|"NODATA"|"ERR";
  error?: string|null;
  location?: LocationInfo;
  answer_preview?: string;
  answer_full?: string;
}
export interface RecordsOverview {
  grid: RRsetCell[];
  consistency: Record<string,"CONSISTENT"|"DRIFT">;
  weak_ttl: string[];
  per_rr_verdict: Record<string,"PASS"|"WARN"|"FAIL">;
  variance_note?: string|null;
  auth_ttl_by_rr: Record<string, number|null>;
  auth_union_present?: boolean;
  auth_union_by_rr?: Record<string, string[]>;
  auth_union_size_by_rr?: Record<string, number>;
  nxdomain_hotspots?: NXDomainHotspot[];
}
export interface DNSSECProbeBreadcrumb {
  ns_ip: string;
  transport: "udp"|"tcp";
  edns: boolean;
  edns_bufsize?: number|null;
  do: boolean;
  rcode: string;
  tc: boolean;
  flags: string[];
  elapsed_ms: number;
  attempt_no: number;
  exception?: string|null;
}
export interface DNSSECLintResult {
  ds_present: boolean;
  ds_match: boolean;
  dnskey_rrsig_valid: boolean;
  rrsig_expiry_hours?: number|null;
  nsec_present?: boolean|null;
  issues: string[];
  state: "SIGNED_VALID"|"SIGNED_BROKEN"|"UNSIGNED"|"INDETERMINATE";
  summary: "PASS"|"WARN"|"FAIL";
  probe_log?: DNSSECProbeBreadcrumb[];
}
export interface DriftRow {
  rr_key: string;
  resolver_id: string;
  role: "public"|"authoritative";
  answers: string[];
  matches_authoritative: boolean;
  dig_cmd: string;
}
export interface DriftAcrossRuns {
  score: number;
  added: Record<string,string[]>;
  removed: Record<string,string[]>;
  modified: Record<string,{from:string[],to:string[]}>;
  diff_rows: DriftRow[];
}
export interface NXDomainHotspot {
  label: string;
  rtype: string;
  resolver_id: string;
  count: number;
  last_rcode: string;
  last_seen_ts: number;
}
export interface AXFRResult {
  ns_name: string;
  ip: string;
  success: boolean;
  error?: string | null;
  rrset_count: number;
}
export interface NameserverHealthItem {
  ns_name: string;
  ip: string;
  family: "IPv4"|"IPv6";
  health_score: number;
  latency_ms_p95: number;
  error_rate: number;
  fallback_used: boolean;
}
export interface NameserverHealth {
  ns: NameserverHealthItem[];
}
export interface RunSummary {
  pass_count: number;
  warn_count: number;
  fail_count: number;
  started_at: number;
  duration_sec: number;
  resolver_count: number;
  records_scanned: number;
}
export interface RunResult {
  run_id: string;
  options: RunOptions;
  phase: Phase;
  progress: number;
  meta: Record<string,any>;
  overview?: RecordsOverview|null;
  dnssec?: DNSSECLintResult|null;
  drift?: DriftAcrossRuns|null;
  ns_health?: NameserverHealth|null;
  axfr_results?: AXFRResult[]|null;
  summary?: RunSummary|null;
  records?: any[];
  errors: string[];
  schema_version?: string;
  generator?: string;
  run?: Record<string,any>;
}
