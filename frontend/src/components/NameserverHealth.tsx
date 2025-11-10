import type { NameserverHealthItem } from "../types";

function healthClass(score: number) {
  if (score >= 80) return "health-badge health-badge--good";
  if (score >= 50) return "health-badge health-badge--warn";
  return "health-badge health-badge--fail";
}

export default function NameserverHealth({ items }: { items: NameserverHealthItem[] }) {
  if (!items.length) return null;
  return (
    <div>
      <div className="table-wrapper">
        <table className="table">
          <thead>
            <tr>
              <th>Nameserver</th>
              <th>IP</th>
              <th>Family</th>
              <th>Health</th>
              <th>Latency p95 (ms)</th>
              <th>Error rate</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item, idx) => (
              <tr key={`${item.ns_name}-${item.ip}-${idx}`}>
                <td>{item.ns_name}</td>
                <td className="cell-mono">{item.ip}</td>
                <td>{item.family}</td>
                <td>
                  <span className={healthClass(item.health_score)}>{item.health_score}</span>
                </td>
                <td>{item.latency_ms_p95.toFixed(1)}</td>
                <td>{(item.error_rate * 100).toFixed(1)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="form-hint">Health based on reachability, latency, and fallback behavior.</p>
    </div>
  );
}
