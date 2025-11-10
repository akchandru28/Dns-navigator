// frontend/src/api.ts
import type { RunOptions, RunResult } from "./types";

// Read env and hard-normalize:
//  - trim spaces
//  - remove trailing slashes
//  - remove one or MORE trailing "/api" segments
const RAW = String(import.meta.env.VITE_API_BASE ?? "http://localhost:8000").trim();

// strip all trailing slashes
let root = RAW.replace(/\/+$/g, "");
// strip one or MORE trailing '/api' segments (handles '/api', '/api/api', '/api/api/api', etc.)
root = root.replace(/(?:\/api)+$/i, "");

const API_ROOT = root;

// Single place to assemble URLs + one-time console debug
function url(path: string) {
  if ((window as any).__api_root_logged !== true) {
    console.log("[DNS Navigator] RAW VITE_API_BASE =", RAW);
    console.log("[DNS Navigator] Normalized API_ROOT =", API_ROOT);
    (window as any).__api_root_logged = true;
  }
  return `${API_ROOT}${path}`;
}

export async function getDefaultResolvers(): Promise<string[]> {
  const r = await fetch(url("/api/resolvers"));
  return r.json();
}
export async function createRun(opts: RunOptions): Promise<{ run_id: string; phase: string }> {
  const r = await fetch(url("/api/run"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(opts),
  });
  if (!r.ok) throw new Error(`Create run failed: ${r.status}`);
  return r.json();
}
export async function getRun(runId: string): Promise<RunResult> {
  const r = await fetch(url(`/api/run/${runId}`));
  if (!r.ok) throw new Error("Run not found");
  return r.json();
}
export function exportJSON(runId: string) { window.open(url(`/api/export/${runId}/json`), "_blank"); }
export function exportCSV(runId: string) { window.open(url(`/api/export/${runId}/csv`), "_blank"); }
