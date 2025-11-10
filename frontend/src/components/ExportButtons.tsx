import { downloadBlob, timestamp } from "../lib/download";

interface ExportButtonsProps {
  domain: string;
  jsonPayload: any;
  csvRows: any[];
}

const CSV_HEADERS = ["qname","qtype","verdict","consistency","status","ttl","auth_union_present","union_miss","no_contradictions","soa_ns_stable","resolvers_consistent"];

export default function ExportButtons({ domain, jsonPayload, csvRows }: ExportButtonsProps) {
  const base = `dns-navigator_${domain}_${timestamp()}`;

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(jsonPayload, null, 2)], { type: "application/json" });
    downloadBlob(blob, `${base}.json`);
  };

  const exportCsv = () => {
    const lines = [
      CSV_HEADERS.join(","),
      ...csvRows.map(row => CSV_HEADERS.map(header => JSON.stringify(row[header] ?? "")).join(","))
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    downloadBlob(blob, `${base}.csv`);
  };

  return (
    <div className="export-buttons">
      <button type="button" onClick={exportCsv} className="btn btn--secondary">Export CSV</button>
      <button type="button" onClick={exportJson} className="btn btn--secondary">Export JSON</button>
    </div>
  );
}
