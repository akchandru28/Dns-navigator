import { useMemo, useState } from "react";
import type { RecordsOverview } from "../types";

interface AxfrSummary {
  attempted?: number;
  success_count?: number;
  record_count?: number;
  errors?: string[];
}

interface RowRecord {
  key: string;
  qname: string;
  qtype: string;
  resolver: string;
  ttlAuth?: number | null;
  ttlRemaining?: number;
  answers: string[];
  status: string;
  error?: string | null;
  answer_preview?: string;
  answer_full?: string;
}

export default function RecordsTable({ ov, axfrSummary }: { ov: RecordsOverview; axfrSummary?: AxfrSummary }) {
  const grouped = useMemo(() => {
    const buckets: Record<string, typeof ov.grid> = {};
    ov.grid.forEach(cell => {
      const key = `${cell.name} ${cell.rtype}`;
      (buckets[key] ||= []).push(cell);
    });
    return buckets;
  }, [ov.grid]);

  const keys = useMemo(() => Object.keys(grouped).sort(), [grouped]);
  const weakSet = useMemo(() => new Set(ov.weak_ttl ?? []), [ov.weak_ttl]);
  const verdicts = ov.per_rr_verdict || {};
  const verdictFor = (key: string) => verdicts[key] ?? (ov.consistency?.[key] === "DRIFT" ? "WARN" : "PASS");
  const hasVariance = useMemo(() => keys.some(k => verdictFor(k) !== "PASS"), [keys, verdicts, ov.consistency]);
  const authTTL = ov.auth_ttl_by_rr || {};

  const rows = useMemo<RowRecord[]>(() => {
    return keys.flatMap(key => {
      const [qname, qtype] = key.split(" ");
      return grouped[key].map(cell => ({
        key,
        qname,
        qtype,
        resolver: cell.resolver_id,
        ttlAuth: authTTL[key],
        ttlRemaining: cell.ttl,
        answers: cell.answers,
        status: cell.status,
        error: cell.error,
        answer_preview: cell.answer_preview,
        answer_full: cell.answer_full
      }));
    });
  }, [keys, grouped, authTTL]);

  const [filters, setFilters] = useState({ weakTTL: false, variance: false });

  const rowsFiltered = rows.filter(row => {
    if (filters.weakTTL && !weakSet.has(row.key)) return false;
    if (filters.variance && verdictFor(row.key) === "PASS") return false;
    return true;
  });
  const nxRows = rowsFiltered.filter(r => r.status === "NXDOMAIN");
  const positiveRows = rowsFiltered.filter(r => r.status !== "NXDOMAIN");

  function toggleFilter(target: "weakTTL" | "variance") {
    setFilters(prev => ({ ...prev, [target]: !prev[target] }));
  }

  const hotspots = ov.nxdomain_hotspots ?? [];
  const renderAxfrSummary = () => {
    if (!axfrSummary) return null;
    const attempted = axfrSummary.attempted ?? 0;
    if (attempted === 0) return null;
    const success = axfrSummary.success_count ?? 0;
    const records = axfrSummary.record_count ?? 0;
    const errors: string[] = axfrSummary.errors ?? [];
    const base = `AXFR succeeded from ${success}/${attempted} nameservers (${records} records)`;
    const errorSuffix = success === 0 && errors.length > 0 ? ` — ${errors.join("; ")}` : "";
    return <div className="form-hint">{base}{errorSuffix}</div>;
  };

  const renderAnswers = (row: RowRecord) => {
    const answersRaw = row.answers?.join("; ") || "—";
    if (row.qtype === "TXT") {
      const preview = row.answer_preview || answersRaw;
      const full = row.answer_full || preview;
      return <span className="answers-text block truncate" title={full}>{preview}</span>;
    }
    return <span className="answers-text block truncate" title={answersRaw}>{answersRaw}</span>;
  };

  return (
    <div className="records-table">
      <div className="filter-chips">
        <button
          type="button"
          className={`filter-chip ${filters.weakTTL ? "filter-chip--active" : ""}`}
          onClick={() => toggleFilter("weakTTL")}
          disabled={weakSet.size === 0}
        >
          Weak TTL
        </button>
        <button
          type="button"
          className={`filter-chip ${filters.variance ? "filter-chip--active" : ""}`}
          onClick={() => toggleFilter("variance")}
          disabled={!hasVariance}
        >
          Resolver variance (geo/CDN)
        </button>
      </div>

      {hotspots.length > 0 && (
      <div className="hotspots mb-4">
        <div className="label" title="Aggregated negative responses by label/type/resolver.">
          NX domain hot spots
        </div>
        <div className="table-wrapper">
          <table className="records-table__table table-fixed w-full">
            <colgroup>
              <col className="w-[34%]" />  {/* RRset (same front as NX domain table) */}
              <col className="w-[14%]" />  {/* Type */}
              <col className="w-[22%]" />  {/* Resolver */}
              <col className="w-[12%]" />  {/* Hits */}
              <col className="w-[18%]" />  {/* Last RCODE */}
            </colgroup>
            <thead>
              <tr>
                <th>RRset</th>
                <th>Type</th>
                <th>Resolver</th>
                <th className="text-right tabular-nums">Hits</th>
                <th>Last RCODE</th>
              </tr>
            </thead>
            <tbody>
              {hotspots.map((h, idx) => (
                <tr key={`${h.label}-${h.rtype}-${h.resolver_id}-${idx}`}>
                  <td className="cell-mono">{h.label}</td>
                  <td>{h.rtype}</td>
                  <td className="cell-mono">{h.resolver_id}</td>
                  <td className="text-right tabular-nums">{h.count}</td>
                  <td>{h.last_rcode}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )}

      {renderAxfrSummary()}

      {positiveRows.length > 0 && (
        <div className="records-table__wrap mt-4">
          <table className="records-table__table table-fixed w-full">
            <colgroup>
              <col className="w-[30%]" />   {/* RRset */}
              <col className="w-[10%]" />   {/* Type */}
              <col className="w-[22%]" />   {/* Resolver */}
              <col className="w-[10%]" />   {/* Auth TTL */}
              <col className="w-[10%]" />   {/* Remain TTL */}
              <col className="w-[18%]" />   {/* Answers */}
            </colgroup>
            <thead>
              <tr>
                <th>RRset</th>
                <th>Type</th>
                <th>Resolver</th>
                <th className="text-right tabular-nums" title="TTL set by authoritative nameserver.">Auth TTL</th>
                <th className="text-right tabular-nums" title="Time left in resolver cache.">Remain TTL</th>
                <th>Answer(s)</th>
              </tr>
            </thead>
            <tbody>
              {positiveRows.map((row, idx) => (
                <tr key={`${row.key}-${row.resolver}-${idx}`}>
                  <td className="cell-mono">{row.qname}</td>
                  <td>{row.qtype}</td>
                  <td className="cell-mono">{row.resolver}</td>
                  <td className="text-right tabular-nums">{row.ttlAuth ?? "—"}</td>
                  <td className="text-right tabular-nums">{row.ttlRemaining ?? "—"}</td>
                  <td className="answers-cell overflow-hidden">{renderAnswers(row)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {nxRows.length > 0 && (
        <>
          <h4 className="mt-6 text-sm font-semibold text-slate-600">NX domain responses</h4>
          <div className="records-table__wrap records-table__wrap--nx mt-2">
            <table className="records-table__table table-fixed w-full">
              <colgroup>
                <col className="w-[34%]" />  {/* Label */}
                <col className="w-[14%]" />  {/* Type */}
                <col className="w-[34%]" />  {/* Resolver */}
                <col className="w-[18%]" />  {/* Answers */}
              </colgroup>
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Type</th>
                  <th>Resolver</th>
                  <th>Answer(s)</th>
                </tr>
              </thead>
              <tbody>
                {nxRows.map((row, idx) => (
                  <tr key={`nx-${row.key}-${row.resolver}-${idx}`}>
                    <td className="cell-mono">{row.qname}</td>
                    <td>{row.qtype}</td>
                    <td className="cell-mono">{row.resolver}</td>
                    <td className="answers-cell overflow-hidden">
                      <span className="answers-text block truncate" title={row.error || "NXDOMAIN"}>
                        {row.error || "NXDOMAIN"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {rowsFiltered.length === 0 && (
        <p className="text-muted mt-4">No RRsets match the selected filters.</p>
      )}
    </div>
  );
}
