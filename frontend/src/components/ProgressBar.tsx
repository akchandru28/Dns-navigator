import type { Phase } from "../types";

const LABELS: Record<Phase,string> = {
  Idle: "Idle",
  Queued: "Queued",
  Probing: "Probing",
  Validating: "Validating",
  Analyzing: "Analyzing",
  Reporting: "Reporting",
  Completed: "Completed",
  Error: "Error"
};

export default function ProgressBar({progress, phase}:{progress:number, phase:Phase}) {
  const safeProgress = Math.max(0, Math.min(100, progress));
  const phaseLabel = LABELS[phase];
  return (
    <div className="progress-wrapper">
      <div className="progress-label" aria-live="polite">
        {safeProgress}% Completed
      </div>
      <div
        className="progress"
        role="progressbar"
        aria-valuenow={safeProgress}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuetext={`${safeProgress}% ${phaseLabel}`}
      >
        <div className="progress__bar" style={{width:`${safeProgress}%`}} />
      </div>
    </div>
  );
}
