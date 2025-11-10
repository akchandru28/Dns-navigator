import type { DNSSECLintResult } from "../types";

export default function DnssecPanel({ res }: { res: DNSSECLintResult }) {
  const issues = Array.isArray(res.issues) ? res.issues : [];
  const badge = (() => {
    switch (res.state) {
      case "SIGNED_VALID":
        return { label: "Signed & valid", className: "dnssec-chip dnssec-chip--pass", note: "Chain validates end-to-end." };
      case "SIGNED_BROKEN":
        return { label: "Signed but broken", className: "dnssec-chip dnssec-chip--fail", note: "Parent DS doesn't match child DNSKEY (or DNSKEY/RRSIG missing). Validators will fail." };
      case "INDETERMINATE":
        return { label: "Indeterminate", className: "dnssec-chip dnssec-chip--warn", note: "DNSKEY fetch failed across authoritative nameservers; see exports for probe details." };
      default:
        return { label: "Unsigned", className: "dnssec-chip dnssec-chip--neutral", note: "No DS at parent. DNSSEC isn't enabled for this zone." };
    }
  })();

  return (
    <div className="dnssec-panel">
      {/* Header */}
      <header className="dnssec-header flex items-center gap-3">
        <h3 className="dnssec-title">DNSSEC linting</h3>
        <span className={badge.className}>{badge.label}</span>
      </header>

      <p className="dnssec-note">{badge.note}</p>

      {/* Remediation (only when truly broken) */}
      {res.state === "SIGNED_BROKEN" && issues.length > 0 && (
        <section className="remediation mt-3">
          <h4 className="mb-2 font-semibold">Fix the following to pass DNSSEC linting:</h4>
          <ul className="list-disc pl-5 text-sm text-slate-700">
            {issues.map((t, i) => <li key={i}>{t}</li>)}
          </ul>
        </section>
      )}
    </div>
  );
}
