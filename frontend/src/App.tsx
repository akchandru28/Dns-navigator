import "./styles.css";
import Header from "./components/Header";
import RunForm from "./components/RunForm";
import { Section } from "./components/Accordion";
import RecordsTable from "./components/RecordsTable";
import DnssecPanel from "./components/DnssecPanel";
import DiffGrid from "./components/DiffGrid";
import ResolverCoverage from "./components/ResolverCoverage";
import NameserverHealth from "./components/NameserverHealth";
import EmptyState from "./components/EmptyState";
import { useRunStore } from "./state/useRunStore";
import ExportButtons from "./components/ExportButtons";
import SummaryPills from "./components/SummaryPills";

export default function App() {
  const { current, loading } = useRunStore();
  return (
    <div className="page">
      <Header />
      <main className="page-main">
        <RunForm />

        {!current ? (
          <EmptyState />
        ) : (
          <>
            <div className="summary-row">
              {current.summary ? (
                <SummaryPills
                  passC={current.summary.pass_count ?? 0}
                  warnC={current.summary.warn_count ?? 0}
                  failC={current.summary.fail_count ?? 0}
                />
              ) : (
                <div className="text-muted text-sm">Run summary pending…</div>
              )}
              <div className="summary-actions summary-actions--top">
                <ExportButtons
                  domain={current.run?.domain || current.options?.domain || current.run_id}
                  jsonPayload={current}
                  csvRows={current.records ?? []}
                />
              </div>
            </div>
            {current.overview && !current.overview.auth_union_present && (
              <div className="banner banner--warn">
                Authoritative nameserver sampling unavailable; results are advisory.
              </div>
            )}

            <Section title="Drift details" defaultOpen>
              {current.overview && (
                <DiffGrid
                  ov={current.overview}
                  diffRows={current.drift?.diff_rows ?? []}
                  driftScore={current.drift?.score ?? 0}
                />
              )}
            </Section>

            <Section title="Zone analytics">
              {current.overview && <RecordsTable ov={current.overview} axfrSummary={current.meta?.axfr_summary} />}
            </Section>

            <Section title="DNSSEC linting">
              {current.dnssec ? (
                <DnssecPanel res={current.dnssec} />
              ) : (
                <div className="text-muted">DNSSEC results not available for this run.</div>
              )}
            </Section>

            <Section title="Resolver coverage">
              <ResolverCoverage
                authority={(current.meta?.auth_ns || []).map((x: any) => `${x[0]}@${x[1]}`)}
                publicResolvers={current.options?.resolvers}
              />
            </Section>

            <Section title="Nameserver health">
              {current.ns_health?.ns?.length ? (
                <NameserverHealth items={current.ns_health!.ns} />
              ) : (
                <div className="text-muted">No nameserver telemetry collected for this run.</div>
              )}
            </Section>

            <Section title="Artifacts & history">
              <div className="artifacts-row">
                <div>Run ID: <code>{current.run_id}</code></div>
                <div>Records scanned: <strong>{current.summary?.records_scanned ?? 0}</strong></div>
                <div>Resolvers: <strong>{current.summary?.resolver_count ?? 0}</strong></div>
                {current.errors?.length > 0 && (
                  <div className="text-error">Errors: {current.errors.join("; ")}</div>
                )}
              </div>
            </Section>
          </>
        )}
      </main>
    </div>
  );
}
