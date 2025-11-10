import { ReactNode, useId, useState } from "react";

export function Section({ title, children, defaultOpen = false }: { title: string; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const bodyId = useId();
  return (
    <div className="accordion">
      <button
        type="button"
        className="accordion__header"
        onClick={() => setOpen(o => !o)}
        aria-expanded={open}
        aria-controls={bodyId}
      >
        <span className="accordion__label" title={title}>{title}</span>
        <span className="accordion__chevron" aria-hidden="true">{open ? "▾" : "▸"}</span>
      </button>
      <div id={bodyId} className="accordion__body" hidden={!open}>
        {children}
      </div>
    </div>
  );
}
