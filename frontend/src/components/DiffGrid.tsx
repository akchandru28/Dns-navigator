import { Fragment, useMemo, useState } from "react";
import type { DriftRow, RecordsOverview } from "../types";

interface Props {
  ov: RecordsOverview;
  diffRows: DriftRow[];
  driftScore: number;
}

export default function DiffGrid({ ov, diffRows, driftScore }: Props) {
  const verdicts = ov.per_rr_verdict || {};
  const fallbackKeys = Object.keys(ov.consistency || {});
  const allKeys = useMemo(() => {
    const keys = Object.keys(verdicts);
    const source = keys.length ? keys : fallbackKeys;
    return [...source].sort();
  }, [verdicts, fallbackKeys]);
  const driftKeys = useMemo(() => Array.from(new Set(diffRows.map(row => row.rr_key))), [diffRows]);

  const verdictFor = (key: string) => verdicts[key] || (ov.consistency?.[key] === "DRIFT" ? "WARN" : "PASS");
  const varianceKeys = useMemo(() => {
    const flagged = new Set(allKeys.filter(k => verdictFor(k) !== "PASS"));
    driftKeys.forEach(k => flagged.add(k));
    return Array.from(flagged).sort();
  }, [allKeys, driftKeys, verdicts, ov.consistency]);
  const [active, setActive] = useState<string | null>(null);

  const grouped = useMemo(() => {
    const map: Record<string, { public: DriftRow[]; authoritative: DriftRow[] }> = {};
    if (varianceKeys.length === 0) return map;
    const keySet = new Set(varianceKeys);
    diffRows.forEach(row => {
      if (!keySet.has(row.rr_key)) return;
      const bucket = map[row.rr_key] || { public: [], authoritative: [] };
      bucket[row.role].push(row);
      map[row.rr_key] = bucket;
    });
    return map;
  }, [diffRows, varianceKeys]);

  const scoreClass =
    driftScore <= 10 ? "drift-score--low" :
    driftScore <= 35 ? "drift-score--med" : "drift-score--high";

  return (
    <div>
      <h3 className="section-subtitle">Resolver variance & diff</h3>
      <div className="drift-header">
        <span className={`drift-score ${scoreClass}`} title="Lower is better. Variance across public resolvers is common with CDNs.">
          Drift score: {driftScore}
        </span>
      </div>
      {varianceKeys.length === 0 ? (
        <p className="text-muted" style={{ marginTop: 8 }}>No variance detected across the requested resolvers.</p>
      ) : (
        <p className="text-muted" style={{ marginTop: 8 }}>
          Some resolver variance detected (common with CDNs).
        </p>
      )}
      {varianceKeys.length > 0 && (
        <div className="drift-list">
          {varianceKeys.map(key => (
            <div key={key} className="drift-item">
              <div className="drift-item__row">
                <code>{key}</code>
                <button
                  type="button"
                  className="text-button diff-toggle"
                  aria-expanded={active === key}
                  aria-label={active === key ? `Hide diff for ${key}` : `View diff for ${key}`}
                  onClick={() => setActive(prev => prev === key ? null : key)}
                >
                  <svg
                    className={`chevron ${active === key ? "chevron--open" : ""}`}
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    aria-hidden="true"
                  >
                    <path d="M5.23 7.21a.75.75 0 011.06.02L10 10.94l3.71-3.71a.75.75 0 011.08 1.04l-4.25 4.25a.75.75 0 01-1.06 0L5.21 8.27a.75.75 0 01.02-1.06z" />
                  </svg>
                </button>
              </div>
              {active === key && (
                <div className="diff-drawer">
                  <table className="diff-table w-full table-auto">
                    <colgroup>
                      <col className="w-[38%]" />
                      <col className="w-[42%]" />
                      <col className="w-[20%]" />
                    </colgroup>
                    <thead>
                      <tr>
                        <th>Resolver / NS</th>
                        <th>Returned answers</th>
                        <th className="text-center">Matches authoritative set</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(!grouped[key] || (!grouped[key].public.length && !grouped[key].authoritative.length)) && (
                        <tr>
                          <td colSpan={3} className="text-muted">No resolver data available for this RRset.</td>
                        </tr>
                      )}
                      {["public", "authoritative"].map(group => {
                        const rows = grouped[key]?.[group as "public" | "authoritative"] || [];
                        if (!rows.length) return null;
                        return (
                          <Fragment key={`${key}-${group}`}>
                            <tr className="diff-group-row">
                              <td colSpan={3}>{group === "public" ? "Public resolvers" : "Authoritative nameservers"}</td>
                            </tr>
                              {rows.map((row, idx) => (
                              <tr key={`${row.resolver_id}-${idx}`} className="align-middle border-b border-slate-100 last:border-0">
                                <td className="py-2">{row.resolver_id}</td>
                                <td className="py-2 font-mono whitespace-pre-wrap break-words" title={row.answers.join(", ") || "—"}>
                                  {row.answers.length ? row.answers.join(", ") : "—"}
                                </td>
                                <td className="py-2 text-center">
                                  <div className="flex items-center justify-center">
                                    <span className={row.matches_authoritative ? "tag tag--yes" : "tag tag--no"}>
                                      {row.matches_authoritative ? "Yes" : "No"}
                                    </span>
                                  </div>
                                </td>
                              </tr>
                            ))}
                          </Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
